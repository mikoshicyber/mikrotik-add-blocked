import ctypes
import io
import os
import ssl
import subprocess
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

import add_blocked as tool


def row(address, rid='*1', **kwargs):
    return {'address': address, '.id': rid, 'list': 'blocked', **kwargs}


class FakeAPI:
    def __init__(self, rows=(), fail=None):
        self.rows = list(rows)
        self.calls = []
        self.fail = fail
        self.closed = False

    def __call__(self, cmd, /, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.fail == cmd:
            raise TimeoutError('secret-test-value')
        return iter(self.rows if cmd.endswith('/print') else ())

    def rawCmd(self, cmd, *words):
        return self(cmd, words=words)

    def close(self):
        self.closed = True


class Tests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.config = Path(directory.name) / tool.CONFIG_FILE
        self.config.touch(mode=0o600)
        config_patch = patch.object(tool, 'CONFIG_FILE', str(self.config))
        config_patch.start()
        self.addCleanup(config_patch.stop)

    def run_cli(self, api, *args):
        with patch.object(tool, 'connect_router', return_value=api), redirect_stdout(io.StringIO()) as out:
            status = tool.main(list(args))
        return status, out.getvalue()

    def test_normalization(self):
        self.assertEqual(tool.normalize_sites(['EXAMPLE.org.', 'example.org', '192.0.2.2/32',
                                               '192.0.2.2', '192.0.2.9/24', 'пример.рф']),
                         ['example.org', '192.0.2.2', '192.0.2.0/24', 'xn--e1afmkfd.xn--p1ai'])

    def test_invalid_input(self):
        for value in ('http://example.org', '1.2.3.999', '::1', 'a..b', 'a b', '*a.com',
                      '192.0.2.2-192.0.2.1', 'a\n.org', 'a.com..'):
            with self.subTest(value=value), self.assertRaises(tool.ToolError):
                tool.normalize_sites([value])

    def test_range(self):
        self.assertTrue(tool.is_ip_entry('192.0.2.1-192.0.2.9'))

    def test_missing_credentials(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(tool.ToolError):
            tool.get_credentials('/nonexistent/config.conf')

    def test_environment_credentials(self):
        env = {'ADD_BLOCKED_HOST': 'router.example.org', 'ADD_BLOCKED_USER': 'service',
               'ADD_BLOCKED_PASSWORD': 'secret%value'}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(tool.get_credentials(self.config), tuple(env.values()))
            with self.assertRaises(tool.MissingConfigError):
                tool.get_credentials('/nonexistent/config.conf')

    def test_config_credentials(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            path = Path(directory) / 'config'
            path.write_text('[credentials]\nhost=router.example.org\nuser=service\npassword=abc%123\n')
            path.chmod(0o600)
            self.assertEqual(tool.get_credentials(path)[2], 'abc%123')
            if os.name == 'posix':
                path.chmod(0o644)
                with self.assertRaises(tool.ToolError):
                    tool.get_credentials(path)

    def test_tls(self):
        module = types.SimpleNamespace(connect=Mock())
        with patch.dict('sys.modules', {'librouteros': module}), patch.object(
                tool, 'get_credentials', return_value=('router.example.org', 'service', 'secret')):
            tool.connect_router(tool.parse_args(['--list', '--api-ssl']))
        options = module.connect.call_args.kwargs
        self.assertEqual(options['port'], 8729)
        wrapper = options['ssl_wrapper']
        self.assertEqual(wrapper.keywords['server_hostname'], 'router.example.org')
        self.assertTrue(wrapper.func.__self__.check_hostname)
        self.assertEqual(wrapper.func.__self__.verify_mode, ssl.CERT_REQUIRED)

    def test_plain(self):
        module = types.SimpleNamespace(connect=Mock())
        with patch.dict('sys.modules', {'librouteros': module}), patch.object(
                tool, 'get_credentials', return_value=('router.example.org', 'service', 'secret')):
            tool.connect_router(tool.parse_args(['--list', '--api-plain']))
        self.assertEqual(module.connect.call_args.kwargs['port'], 8728)
        self.assertNotIn('ssl_wrapper', module.connect.call_args.kwargs)

    def test_default_plain(self):
        module = types.SimpleNamespace(connect=Mock())
        with patch.dict('sys.modules', {'librouteros': module}), patch.object(
                tool, 'get_credentials', return_value=('router.example.org', 'service', 'secret')), patch.object(
                tool.ssl, 'create_default_context') as context:
            tool.connect_router(tool.parse_args([]))
        self.assertEqual(module.connect.call_args.kwargs['port'], 8728)
        self.assertNotIn('ssl_wrapper', module.connect.call_args.kwargs)
        context.assert_not_called()

    def test_ca_file_enables_tls(self):
        self.assertTrue(tool.parse_args(['--api-ca-file', 'ca.pem']).api_ssl)

    def test_connection_error(self):
        module = types.SimpleNamespace(connect=Mock(side_effect=ssl.SSLError('secret-test-value')))
        with patch.dict('sys.modules', {'librouteros': module}), patch.object(
                tool, 'get_credentials', return_value=('router.example.org', 'service', 'secret')), self.assertLogs(
                tool.LOG, 'ERROR') as logs:
            self.assertEqual(tool.main(['example.org']), 1)
        self.assertIn('Cannot connect to RouterOS (SSLError)', str(logs.output))
        self.assertNotIn('partially applied', str(logs.output))
        self.assertNotIn('secret-test-value', str(logs.output))

    def test_arguments(self):
        for args in (['--clean'], ['--list', '--delete'], ['--resolve-workers', '0'],
                     ['--bulk-size', '0'], ['--api-timeout', 'nan'], ['--resolve-timeout', '-1'],
                     ['--max-delete', '0'], ['--list', 'example.org'], ['--api-ssl', '--api-plain'],
                     ['--api-plain', '--api-ca-file', 'ca.pem']):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                tool.parse_args(args)
            self.assertEqual(exc.exception.code, 2)

    def test_add_idempotent(self):
        api = FakeAPI([row('example.org')])
        status, _ = self.run_cli(api, 'EXAMPLE.org.', 'example.net', 'example.net')
        self.assertEqual(status, 0)
        self.assertEqual(api.calls[-1], (tool.ADDRESS_LIST + '/add', {'list': 'blocked', 'address': 'example.net'}))
        self.assertEqual(len(api.calls), 2)
        self.assertTrue(api.closed)

    def test_dry_run(self):
        api = FakeAPI()
        status, output = self.run_cli(api, '-C', 'example.org')
        self.assertEqual(status, 0)
        self.assertIn('would add example.org', output)
        self.assertEqual(len(api.calls), 1)

    def test_list(self):
        api = FakeAPI([row('example.org'), row('other.org', '*2', list='other')])
        status, output = self.run_cli(api, '--list')
        self.assertEqual((status, output), (0, 'example.org\n'))

    def test_cleanup_protection(self):
        rows = [row('keep.org'), row('192.0.2.1', '*2', dynamic=True, comment='KEEP.org.'),
                row('192.0.2.0/24', '*3'), row('192.0.2.2-192.0.2.8', '*4'),
                row('disabled.org', '*5', disabled=True), row('dynamic.org', '*6', dynamic='TRUE'),
                row('remove.org', '*7'), row('unknown value', '*8')]
        self.assertEqual([r['.id'] for r in tool.removal_plan(rows)], ['*7'])

    def test_cleanup_dry(self):
        api = FakeAPI([row('remove.org')])
        status, output = self.run_cli(api, '--clean', '--dry-run')
        self.assertEqual(status, 0)
        self.assertIn('remove.org', output)
        self.assertEqual(len(api.calls), 1)

    def test_cleanup_apply(self):
        api = FakeAPI([row('remove.org')])
        status, _ = self.run_cli(api, '--clean', '--confirm-clean')
        self.assertEqual(status, 0)
        self.assertEqual(api.calls[-1], (tool.ADDRESS_LIST + '/remove', {'.id': '*1'}))
        self.assertEqual(len(api.calls), 3)

    def test_cleanup_changed_snapshot(self):
        api = FakeAPI()
        with patch.object(tool, 'read_address_list', side_effect=[[row('remove.org')], []]):
            status, _ = self.run_cli(api, '--clean', '--confirm-clean')
        self.assertEqual(status, 1)
        self.assertEqual(api.calls, [])

    def test_delete_limit(self):
        api = FakeAPI([row('a.org'), row('b.org', '*2')])
        status, _ = self.run_cli(api, '-d', '--max-delete', '1', 'a.org', 'b.org')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 1)

    def test_delete_batches(self):
        api = FakeAPI([row('a.org'), row('a.org', '*2'), row('b.org', '*3')])
        status, _ = self.run_cli(api, '-d', '--bulk-size', '2', 'a.org', 'b.org')
        self.assertEqual(status, 0)
        self.assertEqual([kwargs['.id'] for _, kwargs in api.calls[1:]], ['*1,*2', '*3'])

    def test_dynamic_delete(self):
        api = FakeAPI([row('192.0.2.2', dynamic=True)])
        status, _ = self.run_cli(api, '-d', '192.0.2.2')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 1)

    def test_api_read_error(self):
        api = FakeAPI(fail=tool.ADDRESS_LIST + '/print')
        with self.assertLogs(tool.LOG, 'ERROR') as logs:
            status, _ = self.run_cli(api, 'a.org')
        self.assertEqual(status, 1)
        self.assertNotIn('secret-test-value', str(logs.output))
        self.assertEqual(len(api.calls), 1)
        self.assertTrue(api.closed)

    def test_api_write_error_stops(self):
        api = FakeAPI(fail=tool.ADDRESS_LIST + '/add')
        status, _ = self.run_cli(api, 'a.org', 'b.org')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 2)
        self.assertTrue(api.closed)

    def test_partial_removal_failure_stops(self):
        api = FakeAPI([row('a.org'), row('b.org', '*2'), row('c.org', '*3')])
        original = api.__class__.__call__
        def fail_second(self, cmd, **kwargs):
            if kwargs.get('.id') == '*2':
                self.fail = cmd
            return original(self, cmd, **kwargs)
        with patch.object(FakeAPI, '__call__', fail_second):
            status, _ = self.run_cli(api, '-d', '--bulk-size', '1', 'a.org', 'b.org', 'c.org')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 3)
        self.assertTrue(api.closed)

    def test_invalid_router_row(self):
        api = FakeAPI([row('a.org', '')])
        status, _ = self.run_cli(api, 'b.org')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 1)

    def test_version_without_config(self):
        self.config.unlink()
        with redirect_stdout(io.StringIO()) as out, patch.object(tool, 'connect_router') as connect:
            with self.assertRaises(SystemExit) as exc:
                tool.cli(['--version'])
            self.assertEqual(exc.exception.code, 0)
            self.assertEqual(out.getvalue().strip(), tool.__version__)
            connect.assert_not_called()

    def test_compiled_dns_worker_command(self):
        compiled = types.SimpleNamespace(process_exe='compiled.exe')
        with patch.object(tool, '__compiled__', compiled, create=True), patch.object(
                tool.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertTrue(tool.resolve_task('localhost', 5))
            self.assertEqual(run.call_args.args[0], ['compiled.exe', '--_resolve', 'localhost'])
            self.assertEqual(run.call_args.kwargs['timeout'], 5)

    def test_dns_worker_bypasses_config_and_api(self):
        self.config.unlink()
        with patch.object(tool.socket, 'getaddrinfo') as resolve, patch.object(tool, 'connect_router') as connect:
            self.assertEqual(tool.cli(['--_resolve', 'localhost']), 0)
            resolve.assert_called_once_with('localhost', None, proto=tool.socket.IPPROTO_TCP)
            resolve.side_effect = OSError('lookup failed')
            self.assertEqual(tool.cli(['--_resolve', 'localhost']), 1)
            connect.assert_not_called()

    def test_compiled_config_path(self):
        compiled = types.SimpleNamespace(containing_dir=str(self.config.parent))
        with patch.object(tool.os, 'name', 'nt'), patch.object(tool, 'CONFIG_FILE', 'add_blocked.conf'), patch.object(
                tool, '__compiled__', compiled, create=True):
            self.assertEqual(tool.parse_args([]).config, str(self.config))
            self.assertEqual(tool.parse_args(['--list']).config, 'add_blocked.conf')

    def test_dns_timeout(self):
        with patch.object(tool.subprocess, 'run', side_effect=subprocess.TimeoutExpired('python', 1)):
            self.assertFalse(tool.resolve_task('example.org', 1))

    def test_dns_skip_status(self):
        api = FakeAPI()
        with patch.object(tool, 'resolve_task', return_value=False):
            status, _ = self.run_cli(api, '--resolve-timeout', '1', 'example.org')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 1)

    def test_dns_local(self):
        self.assertTrue(tool.resolve_task('localhost', 5))
        self.assertTrue(tool.resolve_task('192.0.2.0/24', 1))

    def test_file_and_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'entries.txt'
            path.write_bytes(b'\xef\xbb\xbf# list\n\nexample.org\n')
            self.assertEqual(tool.read_sites_from_source(str(path), tool.parse_args([])), ['example.org'])

    def test_source_size(self):
        with patch.object(tool, 'MAX_SOURCE_BYTES', 3), self.assertRaises(tool.ToolError):
            tool.read_limited(io.BytesIO(b'1234'))

    def test_http_rejected(self):
        with self.assertRaises(tool.ToolError):
            tool.read_sites_from_source('http://example.org', tool.parse_args([]))

    def test_redirect_rejected(self):
        from urllib.request import Request
        handler = tool.SourceRedirectHandler()
        with self.assertRaises(tool.ToolError):
            handler.redirect_request(Request('https://example.org'), None, 302, '', {}, 'http://example.org')

    def test_close_error(self):
        api = FakeAPI()
        api.close = Mock(side_effect=OSError('secret-test-value'))
        status, _ = self.run_cli(api, '--list')
        self.assertEqual(status, 1)

    def test_invalid_input_prevents_connection(self):
        with patch.object(tool, 'connect_router') as connect:
            self.assertEqual(tool.main(['example.org', 'bad/address']), 1)
            connect.assert_not_called()

    def test_source_read_error_prevents_connection(self):
        with patch.object(tool, 'connect_router') as connect:
            self.assertEqual(tool.main(['-f', '/nonexistent/input.txt']), 1)
            connect.assert_not_called()

    def test_server_side_query(self):
        api = FakeAPI([row('a.org')])
        status, _ = self.run_cli(api, '--list')
        self.assertEqual(status, 0)
        self.assertEqual(api.calls[0], (tool.ADDRESS_LIST + '/print', {'words': (
            '=.proplist=.id,list,address,dynamic,disabled,comment', '?list=blocked')}))

    def test_preview_above_deletion_limit(self):
        api = FakeAPI([row('a.org'), row('b.org', '*2')])
        status, output = self.run_cli(api, '-d', '-C', '--max-delete', '1', 'a.org', 'b.org')
        self.assertEqual(status, 0)
        self.assertIn('a.org', output)
        self.assertIn('b.org', output)
        self.assertEqual(len(api.calls), 1)

    def test_duplicate_router_ids(self):
        api = FakeAPI([row('a.org'), row('b.org')])
        status, _ = self.run_cli(api, 'c.org')
        self.assertEqual(status, 1)
        self.assertEqual(len(api.calls), 1)

    def test_interactive_add(self):
        api = FakeAPI()
        with patch('sys.stdin', io.StringIO('example.org example.net\n')):
            status, output = self.run_cli(api, '-C')
        self.assertEqual(status, 0)
        self.assertIn('Enter domains or HTTP(S) URLs. Add -d to delete.', output)
        self.assertIn('would add example.org', output)
        self.assertIn('would add example.net', output)
        self.assertEqual(len(api.calls), 1)

    def test_interactive_urls(self):
        api = FakeAPI()
        with patch('sys.stdin', io.StringIO(
                'EXAMPLE.org HTTPS://example.org:443/path?q=1#fragment http://www.example.net/a https://192.0.2.1/\n')), patch.object(
                tool, 'build_opener') as opener:
            status, _ = self.run_cli(api)
        self.assertEqual(status, 0)
        self.assertEqual([kwargs['address'] for _, kwargs in api.calls[1:]],
                         ['example.org', 'www.example.net', '192.0.2.1'])
        opener.assert_not_called()

    def test_interactive_url_delete(self):
        api = FakeAPI([row('www.example.org')])
        with patch('sys.stdin', io.StringIO('-d https://www.example.org/path\n')):
            status, _ = self.run_cli(api)
        self.assertEqual(status, 0)
        self.assertEqual(api.calls[-1], (tool.ADDRESS_LIST + '/remove', {'.id': '*1'}))

    def test_invalid_interactive_urls(self):
        for url in ('https://', 'ftp://example.org/a', 'https://user:password@example.org/',
                    'https://example.org:invalid/', 'https://example.org:65536/',
                    'https://example.org:0/', 'https://example.org:/', 'https://[::1]/',
                    'https://example.org\\evil.org/', 'https://bad..org/'):
            with self.subTest(url=url), patch('sys.stdin', io.StringIO(f'{url}\n')), patch.object(
                    tool, 'connect_router') as connect, redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main([]), 1)
                connect.assert_not_called()

    def test_url_inputs_remain_strict_outside_prompt(self):
        with patch.object(tool, 'connect_router') as connect:
            self.assertEqual(tool.main(['https://example.org/path']), 1)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'entries.txt'
                path.write_text('https://example.org/path\n')
                self.assertEqual(tool.main(['-f', str(path)]), 1)
            connect.assert_not_called()

    def test_interactive_url_idna_and_cidr(self):
        self.assertEqual(tool.normalize_sites(['https://пример.рф/a', '192.0.2.9/24'], allow_urls=True),
                         ['xn--e1afmkfd.xn--p1ai', '192.0.2.0/24'])

    def test_interactive_delete(self):
        api = FakeAPI([row('example.org'), row('example.net', '*2')])
        with patch('sys.stdin', io.StringIO('example.org -d example.net\n')):
            status, _ = self.run_cli(api)
        self.assertEqual(status, 0)
        self.assertEqual(api.calls[-1], (tool.ADDRESS_LIST + '/remove', {'.id': '*1,*2'}))

    def test_interactive_delete_flag(self):
        api = FakeAPI([row('example.org')])
        with patch('sys.stdin', io.StringIO('example.org\n')):
            status, output = self.run_cli(api, '-d', '-C')
        self.assertEqual(status, 0)
        self.assertIn('would remove example.org', output)

    def test_interactive_empty_or_eof(self):
        for data, expected in (('\n', 0), ('-d\n', 0), ('', 1)):
            with self.subTest(data=data), patch('sys.stdin', io.StringIO(data)), patch.object(
                    tool, 'connect_router') as connect, redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main([]), expected)
                connect.assert_not_called()

    def test_explicit_modes_do_not_prompt(self):
        with patch('builtins.input', side_effect=AssertionError('unexpected prompt')) as prompt:
            for args in (('--list',), ('--clean', '-C'), ('example.org', '-C')):
                status, _ = self.run_cli(FakeAPI(), *args)
                self.assertEqual(status, 0)
            prompt.assert_not_called()

    def test_windows_console_restores_missing_streams(self):
        for existing_console in (0, 65001):
            kernel = Mock()
            kernel.GetConsoleCP.return_value = existing_console
            kernel.AllocConsole.return_value = 1
            streams = [io.StringIO() for _ in range(3)]
            with self.subTest(existing_console=existing_console), patch.object(
                    ctypes, 'WinDLL', return_value=kernel, create=True), patch.object(
                    tool.os, 'name', 'nt'), patch('sys.stdin', None), patch('sys.stdout', None), patch(
                    'sys.stderr', None), patch('builtins.open', side_effect=streams) as opener:
                tool.restore_windows_console()
                self.assertIs(tool.sys.stdin, streams[0])
                self.assertIs(tool.sys.stdout, streams[1])
                self.assertIs(tool.sys.stderr, streams[2])
                self.assertEqual(kernel.AllocConsole.call_count, int(not existing_console))
                self.assertEqual([call.args[0] for call in opener.call_args_list],
                                 ['CONIN$', 'CONOUT$', 'CONOUT$'])

    def test_windows_console_preserves_existing_streams(self):
        with patch.object(tool.os, 'name', 'nt'), patch('sys.stdin', io.StringIO()), patch(
                'sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()), patch.object(
                ctypes, 'WinDLL', create=True) as kernel:
            tool.restore_windows_console()
            kernel.assert_not_called()

    def test_windows_console_restored_before_main(self):
        with patch.object(tool, 'restore_windows_console') as restore, patch.object(
                tool, 'main', side_effect=lambda argv: 0 if restore.called else 1), patch(
                'sys.stdin', io.StringIO()):
            self.assertEqual(tool.cli([]), 0)
            restore.assert_called_once_with()
            restore.reset_mock()
            self.assertEqual(tool.cli(['--list']), 1)
            restore.assert_not_called()

    def test_windows_default_config_path(self):
        with patch.object(tool.os, 'name', 'nt'), patch.object(tool, 'CONFIG_FILE', 'add_blocked.conf'):
            self.assertEqual(tool.parse_args([]).config,
                             os.path.join(os.path.dirname(tool.__file__), tool.CONFIG_FILE))
            self.assertEqual(tool.parse_args(['--list']).config, tool.CONFIG_FILE)
            self.assertEqual(tool.parse_args(['--config', 'custom.conf']).config, 'custom.conf')

    def test_cli_pause_after_success_or_error(self):
        for status in (0, 1):
            with self.subTest(status=status), patch('sys.stdin', Mock(isatty=Mock(return_value=True))), patch(
                    'sys.stdout', Mock(isatty=Mock(return_value=True))), patch.object(
                    tool, 'main', return_value=status) as main, patch('builtins.input') as prompt:
                self.assertEqual(tool.cli([]), status)
                main.assert_called_once_with([])
                prompt.assert_called_once_with('Press Enter to exit...')

    def test_cli_no_pause(self):
        for argv, stdin_tty, stdout_tty, status in ((['example.org'], True, True, 0),
                ([], False, True, 0), ([], True, False, 1), ([], True, True, 130)):
            with self.subTest(argv=argv, stdin_tty=stdin_tty, stdout_tty=stdout_tty, status=status), patch(
                    'sys.stdin', Mock(isatty=Mock(return_value=stdin_tty))), patch(
                    'sys.stdout', Mock(isatty=Mock(return_value=stdout_tty))), patch.object(
                    tool, 'main', return_value=status), patch('builtins.input') as prompt:
                self.assertEqual(tool.cli(argv), status)
                prompt.assert_not_called()

    def test_cli_startup_error_pauses(self):
        with patch('sys.stdin', Mock(isatty=Mock(return_value=True))), patch(
                'sys.stdout', Mock(isatty=Mock(return_value=True))), patch.object(
                tool, 'main', side_effect=RuntimeError('secret-test-value')), patch(
                'builtins.input') as prompt, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(tool.cli([]), 1)
            self.assertIn('Startup failed (RuntimeError)', err.getvalue())
            self.assertNotIn('secret-test-value', err.getvalue())
            prompt.assert_called_once_with('Press Enter to exit...')

    def test_cli_pause_interrupted(self):
        for exc in (EOFError, KeyboardInterrupt):
            with self.subTest(exc=exc), patch('sys.stdin', Mock(isatty=Mock(return_value=True))), patch(
                    'sys.stdout', Mock(isatty=Mock(return_value=True))), patch.object(
                    tool, 'main', return_value=1), patch('builtins.input', side_effect=exc):
                self.assertEqual(tool.cli([]), 1)

    def test_missing_config_prints_help_before_input_or_network(self):
        self.config.unlink()
        for argv in ([], ['--list'], ['-f', 'https://example.org/list'], ['example.org']):
            with self.subTest(argv=argv), patch.object(tool, 'wait_for_key') as pause, patch.object(
                    tool, 'connect_router') as connect, patch.object(tool, 'read_sites_from_source') as source, patch(
                    'builtins.input') as prompt, redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                self.assertEqual(tool.cli(argv), 1)
                self.assertIn('usage:', out.getvalue())
                self.assertIn('[credentials]', out.getvalue())
                self.assertIn(str(self.config), err.getvalue())
                pause.assert_called_once_with()
                prompt.assert_not_called()
                source.assert_not_called()
                connect.assert_not_called()

    def test_missing_explicit_config_and_help(self):
        missing = self.config.parent / 'custom.conf'
        with patch.object(tool, 'wait_for_key') as pause, redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            self.assertEqual(tool.cli(['--config', str(missing), '--list']), 1)
            self.assertIn(str(missing), err.getvalue())
            self.assertIn('usage:', out.getvalue())
            pause.assert_called_once_with()
            pause.reset_mock()
            with self.assertRaises(SystemExit) as exc:
                tool.cli(['--config', str(missing), '--help'])
            self.assertEqual(exc.exception.code, 0)
            pause.assert_not_called()

    def test_missing_config_with_environment_credentials(self):
        self.config.unlink()
        env = {'ADD_BLOCKED_HOST': 'router', 'ADD_BLOCKED_USER': 'service', 'ADD_BLOCKED_PASSWORD': 'secret'}
        with patch.dict(os.environ, env), patch.object(tool, 'connect_router') as connect, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(tool.cli(['--list']), 1)
            connect.assert_not_called()

    def test_wait_for_key_windows(self):
        msvcrt = types.SimpleNamespace(getwch=Mock(return_value='x'))
        with patch.object(tool.os, 'name', 'nt'), patch.dict('sys.modules', {'msvcrt': msvcrt}), patch(
                'sys.stdin', Mock(isatty=Mock(return_value=True))), patch('sys.stdout', Mock(isatty=Mock(return_value=True))), patch('builtins.input') as prompt:
            tool.wait_for_key()
            msvcrt.getwch.assert_called_once_with()
            prompt.assert_not_called()

    def test_wait_for_key_redirected(self):
        with patch('sys.stdin', io.StringIO('x')), redirect_stdout(io.StringIO()) as out:
            tool.wait_for_key()
            self.assertEqual(out.getvalue(), '')

    def test_missing_config_noninteractive_exits(self):
        self.config.unlink()
        with patch('sys.stdin', io.StringIO()), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            self.assertEqual(tool.cli([]), 1)
            self.assertIn('usage:', out.getvalue())
            self.assertNotIn('Press any key', out.getvalue())

    def test_empty_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'entries.txt'
            path.write_text('')
            with patch.object(tool, 'connect_router') as connect:
                self.assertEqual(tool.main(['-f', str(path)]), 0)
            connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
