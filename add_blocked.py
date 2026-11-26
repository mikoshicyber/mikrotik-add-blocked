#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
import ipaddress
import logging
import math
import os
import re
import ssl
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

LOG = logging.getLogger('add_blocked')
CONFIG_FILE = 'add_blocked.conf'
ADDRESS_LIST = '/ip/firewall/address-list'
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
DOMAIN_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
ROW_ID = re.compile(r'\*[0-9a-fA-F]+\Z')


class ToolError(Exception):
    pass


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('expected a finite positive number')
    return number


def nonnegative_float(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError('expected a finite non-negative number')
    return number


def bounded_int(minimum, maximum):
    def parse(value):
        number = int(value)
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f'expected an integer from {minimum} to {maximum}')
        return number
    return parse


def get_credentials(config_file=CONFIG_FILE):
    config = configparser.ConfigParser(interpolation=None)
    mode = None
    try:
        with open(config_file, encoding='utf-8') as stream:
            mode = os.fstat(stream.fileno()).st_mode
            config.read_file(stream)
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise ToolError(f'Cannot read configuration ({type(exc).__name__})') from None

    def setting(key):
        return os.environ.get(f'ADD_BLOCKED_{key.upper()}', config.get('credentials', key, fallback=''))

    host, user, password = (setting(key) for key in ('host', 'user', 'password'))
    if not all((host, user, password)):
        raise ToolError('Host, user and password must be configured explicitly')
    if any(ord(c) < 32 or ord(c) == 127 for c in host + user + password):
        raise ToolError('Control characters in credentials are not allowed')
    if host != host.strip() or any(c.isspace() for c in host) or '/' in host:
        raise ToolError('Host must be a hostname or IP address, without a URL or port')
    if ':' in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise ToolError('Host must not include a port') from None
    if not user.isascii() or not password.isascii():
        raise ToolError('RouterOS credentials must use ASCII characters')
    if (os.name == 'posix' and mode is not None and mode & (stat.S_IRWXG | stat.S_IRWXO)
            and config.get('credentials', 'password', fallback='')):
        raise ToolError('Configuration containing a password must have permissions 0600 or stricter')
    return host, user, password


def is_ip_entry(value):
    try:
        if '/' in value:
            return ipaddress.ip_network(value, strict=False).version == 4
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        first, sep, last = value.partition('-')
        if not sep:
            return False
        try:
            return ipaddress.IPv4Address(first) <= ipaddress.IPv4Address(last)
        except ValueError:
            return False


def normalize_address(value):
    value = value.strip().lower()
    if not value or len(value) > 1024 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid address')
    if is_ip_entry(value):
        if '/' in value:
            network = ipaddress.IPv4Network(value, strict=False)
            return str(network.network_address) if network.prefixlen == 32 else str(network)
        first, sep, last = value.partition('-')
        return first if sep and first == last else value
    if value.endswith('.'):
        value = value[:-1]
    value = value.encode('idna').decode('ascii').lower()
    if (len(value) > 253 or not all(DOMAIN_LABEL.fullmatch(part) for part in value.split('.'))
            or value.split('.')[-1].isdigit()):
        raise ValueError('invalid DNS name')
    return value


def normalize_sites(sites):
    result = {}
    for index, site in enumerate(sites, 1):
        if index > MAX_ENTRIES:
            raise ToolError(f'Input exceeds {MAX_ENTRIES} entries')
        try:
            result[normalize_address(site)] = None
        except (ValueError, UnicodeError):
            raise ToolError(f'Invalid address at input entry {index}') from None
    return list(result)


def router_flag(row, key):
    value = row.get(key, False)
    if isinstance(value, str):
        value = value.lower()
    if value is True or value in ('true', 'yes', '1', 1):
        return True
    if value is False or value in ('false', 'no', '0', 0):
        return False
    raise ToolError(f'Unexpected RouterOS {key} flag')


def row_address(row):
    try:
        return normalize_address(row['address'])
    except (KeyError, TypeError, AttributeError, ValueError, UnicodeError):
        return None


def read_address_list(api, list_name):
    rows = []
    for row in api.rawCmd(f'{ADDRESS_LIST}/print', '=.proplist=.id,list,address,dynamic,disabled,comment',
                          f'?list={list_name}'):
        if row.get('list') != list_name:
            continue
        if len(rows) >= MAX_ENTRIES:
            raise ToolError(f'RouterOS list exceeds {MAX_ENTRIES} entries')
        if not isinstance(row.get('address'), str) or not ROW_ID.fullmatch(str(row.get('.id', ''))):
            raise ToolError('RouterOS returned an incomplete address-list entry')
        rows.append(row)
    if len({row['.id'] for row in rows}) != len(rows):
        raise ToolError('RouterOS returned duplicate entry IDs')
    LOG.debug('Loaded %d rows from list %r', len(rows), list_name)
    return rows


def resolve_task(domain, timeout):
    if is_ip_entry(domain):
        return True
    try:
        result = subprocess.run(
            [sys.executable, '-I', '-c',
             'import socket, sys; socket.getaddrinfo(sys.argv[1], None, proto=socket.IPPROTO_TCP)', domain],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def bulk_resolve(domains, timeout, workers):
    if not domains or timeout == 0:
        return dict.fromkeys(domains, True)
    start = time.monotonic()
    results = {}
    with ThreadPoolExecutor(max_workers=min(len(domains), workers)) as executor:
        for start_index in range(0, len(domains), workers):
            batch = domains[start_index:start_index + workers]
            results.update(zip(batch, executor.map(partial(resolve_task, timeout=timeout), batch)))
    LOG.debug('Resolved %d entries in %.3fs', len(domains), time.monotonic() - start)
    return results


def add_sites(api, sites, rows, args):
    existing = {row_address(row) for row in rows}
    candidates = [site for site in sites if site not in existing]
    results = bulk_resolve(candidates, args.resolve_timeout, args.resolve_workers)
    skipped = [site for site in candidates if not results[site]]
    for site in skipped:
        LOG.warning('DNS lookup failed or timed out: %s', site)
    added = 0
    for site in candidates:
        if not results[site]:
            continue
        if args.dry_run:
            print(f'DRY-RUN: would add {site}')
        else:
            tuple(api(f'{ADDRESS_LIST}/add', **{'list': args.addr_list, 'address': site}))
            LOG.info('Added %s', site)
        added += 1
    LOG.info('%s=%d existing=%d dns_skipped=%d', 'planned_additions' if args.dry_run else 'added',
             added, len(sites) - len(candidates), len(skipped))
    return int(bool(skipped))


def removal_plan(rows, sites=None):
    if sites is not None:
        targets = set(sites)
        return [row for row in rows if row_address(row) in targets and not router_flag(row, 'dynamic')]
    dynamic_comments = {row_address({'address': row.get('comment', '')}) for row in rows
                        if router_flag(row, 'dynamic') and is_ip_entry(row.get('address', ''))}
    return [row for row in rows if not router_flag(row, 'dynamic') and not router_flag(row, 'disabled')
            and (address := row_address(row)) is not None and not is_ip_entry(address)
            and address not in dynamic_comments]


def remove_entries(api, plan, args):
    if len(plan) > args.max_delete:
        if not args.dry_run:
            raise ToolError(f'Deletion plan contains {len(plan)} rows; limit is {args.max_delete}')
        LOG.warning('Deletion plan exceeds the apply limit of %d rows', args.max_delete)
    if args.dry_run:
        for row in plan:
            print(f'DRY-RUN: would remove {row_address(row)} id={row[".id"]}')
    else:
        for offset in range(0, len(plan), args.bulk_size):
            batch = plan[offset:offset + args.bulk_size]
            ids = ','.join(row['.id'] for row in batch)
            tuple(api(f'{ADDRESS_LIST}/remove', **{'.id': ids}))
            for row in batch:
                LOG.info('Removed %s id=%s', row_address(row), row['.id'])
    LOG.info('%s=%d', 'planned_deletions' if args.dry_run else 'removed', len(plan))
    return 0


class SourceRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlsplit(req.full_url), urlsplit(newurl)
        if new.scheme not in ('http', 'https') or (old.scheme == 'https' and new.scheme != 'https'):
            raise ToolError('Unsafe source redirect rejected')
        if new.username is not None or new.password is not None:
            raise ToolError('URL credentials are not supported')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_limited(stream):
    data = stream.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ToolError(f'Source exceeds {MAX_SOURCE_BYTES} bytes')
    return data


def read_sites_from_source(source, args):
    parsed = urlsplit(source)
    if parsed.scheme in ('http', 'https'):
        if parsed.username is not None or parsed.password is not None:
            raise ToolError('URL credentials are not supported')
        if parsed.scheme == 'http' and not args.allow_http:
            raise ToolError('HTTP sources require --allow-http')
        context = ssl.create_default_context()
        if args.insecure:
            LOG.warning('Source HTTPS certificate verification is disabled')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if parsed.scheme == 'http':
            LOG.warning('Using an unencrypted HTTP source')
        opener = build_opener(SourceRedirectHandler(), HTTPSHandler(context=context))
        request = Request(source, headers={'User-Agent': 'addrlist-tool/2.0', 'Accept-Encoding': 'identity'})
        with opener.open(request, timeout=args.source_timeout) as response:
            data = read_limited(response)
            charset = response.headers.get_content_charset() or 'utf-8-sig'
    else:
        if '://' in source:
            raise ToolError('Unsupported source URL scheme')
        with open(source, 'rb') as stream:
            data = read_limited(stream)
        charset = 'utf-8-sig'
    lines = [line.strip() for line in data.decode(charset).splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    LOG.info('Loaded %d input entries', len(lines))
    return lines


def connect_router(args):
    try:
        from librouteros import connect
    except ImportError:
        raise ToolError('Missing dependency: install requirements.txt') from None
    host, user, password = get_credentials(args.config)
    options = dict(host=host, username=user, password=password, timeout=args.api_timeout,
                   port=args.api_port or (8728 if args.api_plain else 8729))
    if args.api_plain:
        LOG.warning('Using unencrypted RouterOS API; restrict access to a trusted management network')
    else:
        context = ssl.create_default_context(cafile=args.api_ca_file)
        options['ssl_wrapper'] = partial(context.wrap_socket, server_hostname=host)
    api = connect(**options)
    LOG.info('Connected to RouterOS')
    return api


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='MikroTik IPv4 firewall address-list tool')
    parser.add_argument('sites', nargs='*', help='DNS names, IPv4 addresses, networks or ranges')
    parser.add_argument('-f', '--file', help='Local file or HTTP(S) URL with one entry per line')
    parser.add_argument('--source-timeout', type=positive_float, default=10.0)
    parser.add_argument('--insecure', action='store_true', help='Disable HTTPS verification for the source only')
    parser.add_argument('--allow-http', action='store_true', help='Allow unencrypted HTTP sources')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('-d', '--delete', action='store_true', help='Delete specified static entries')
    mode.add_argument('-l', '--list', action='store_true', help='List current addresses')
    mode.add_argument('-c', '--clean', action='store_true', help='Find static DNS entries without dynamic IPv4 children')
    parser.add_argument('-A', '--addr-list', default='blocked')
    parser.add_argument('-C', '--dry-run', action='store_true')
    parser.add_argument('--confirm-clean', action='store_true', help='Explicitly permit cleanup writes')
    parser.add_argument('--max-delete', type=bounded_int(1, MAX_ENTRIES), default=100)
    parser.add_argument('--bulk-size', type=bounded_int(1, 1000), default=50)
    parser.add_argument('--resolve-timeout', type=nonnegative_float, default=0.0)
    parser.add_argument('--resolve-workers', type=bounded_int(1, 128), default=32)
    parser.add_argument('--config', default=CONFIG_FILE)
    parser.add_argument('--api-timeout', type=positive_float, default=10.0)
    parser.add_argument('--api-port', type=bounded_int(1, 65535))
    parser.add_argument('--api-plain', action='store_true', help='Use legacy unencrypted API explicitly')
    parser.add_argument('--api-ca-file', help='Trusted CA certificate file for RouterOS TLS')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args(argv)
    if not args.addr_list.strip() or not args.addr_list.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in args.addr_list):
        parser.error('--addr-list must be a non-empty ASCII list name without control characters')
    if args.clean and not (args.dry_run or args.confirm_clean):
        parser.error('--clean requires --dry-run or --confirm-clean')
    if args.confirm_clean and not args.clean:
        parser.error('--confirm-clean requires --clean')
    if (args.clean or args.list) and (args.sites or args.file):
        parser.error('--clean and --list do not accept input entries')
    if args.api_plain and args.api_ca_file:
        parser.error('--api-ca-file cannot be used with --api-plain')
    return args


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logging.getLogger('librouteros').setLevel(logging.CRITICAL + 1)
    api = None
    status = 0
    try:
        if args.file:
            args.sites.extend(read_sites_from_source(args.file, args))
        if not args.sites and not (args.list or args.clean):
            if args.file:
                LOG.info('No input entries')
                return 0
            if not sys.stdin.isatty():
                raise ToolError('No input entries; supply addresses or --file')
            entries = input('Enter addresses; add -d to delete:\n').split()
            args.delete = args.delete or '-d' in entries
            args.sites = [entry for entry in entries if entry != '-d']
            if not args.sites:
                return 0
        sites = normalize_sites(args.sites)
        api = connect_router(args)
        rows = read_address_list(api, args.addr_list)
        if args.list:
            for row in rows:
                print(row['address'])
        elif args.clean or args.delete:
            if args.delete:
                targets = set(sites)
                dynamic = sum(row_address(row) in targets and router_flag(row, 'dynamic') for row in rows)
                if dynamic:
                    LOG.warning('Ignoring %d dynamic rows; remove the owning static entry instead', dynamic)
            if args.clean:
                LOG.warning('Cleanup uses dynamic IPv4 comments, not proof of DNS nonexistence')
            plan = removal_plan(rows, None if args.clean else sites)
            if args.clean and not args.dry_run and plan:
                fresh_plan = removal_plan(read_address_list(api, args.addr_list))
                if {(row['.id'], row_address(row)) for row in plan} != {
                        (row['.id'], row_address(row)) for row in fresh_plan}:
                    raise ToolError('Cleanup plan changed; review a new dry-run before retrying')
                plan = fresh_plan
            status = remove_entries(api, plan, args)
            if args.delete and dynamic:
                status = 1
        else:
            status = add_sites(api, sites, rows, args)
    except ToolError as exc:
        LOG.error('%s', exc)
        status = 1
    except KeyboardInterrupt:
        LOG.warning('Interrupted; previously applied changes are not rolled back')
        status = 130
    except Exception as exc:
        LOG.error('Operation failed (%s); changes may have been partially applied. Re-read the list before retrying',
                  type(exc).__name__)
        status = 1
    finally:
        if api is not None:
            try:
                api.close()
            except Exception as exc:
                LOG.error('API close failed (%s)', type(exc).__name__)
                if status == 0:
                    status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
