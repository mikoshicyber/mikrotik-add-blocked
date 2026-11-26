# MikroTik Address List Tool

English | [Русский](README.ru.md)

A command-line utility for managing IPv4 firewall address lists in MikroTik RouterOS using the native API. It supports adding and removing DNS names, IPv4 addresses, networks and ranges, listing entries, and reviewing potentially stale DNS entries.

## Requirements

- Python 3.10 or newer (use a currently supported, patched Python release).
- `librouteros==4.2.2`, installed from `requirements.txt`.
- RouterOS 6.43 or newer as the intended authentication baseline; validate against your exact RouterOS release before deployment.
- A dedicated RouterOS account with the minimum required API and read/write permissions. Use a read-only account for listing or preview-only jobs where possible.
- A reachable `api-ssl` service with a trusted certificate (TCP 8729 by default). Restrict access to the management network and authorized source addresses.

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python add_blocked.py --help
```

The commands above use a POSIX shell. On Windows, activate the virtual environment using its platform-specific activation script.

## Configuration

```bash
install -m 600 add_blocked.conf.example add_blocked.conf
```

Edit `add_blocked.conf` in the current working directory, or select a different path with `--config`:

```ini
[credentials]
host = router.example.org
user = address-list-service
password =
```

Provide the actual password through a protected configuration file or the `ADD_BLOCKED_PASSWORD` environment variable injected by a secret manager or scheduler. The three environment variables `ADD_BLOCKED_HOST`, `ADD_BLOCKED_USER` and `ADD_BLOCKED_PASSWORD` override their respective INI values, including empty values. All three settings must be non-empty. Credentials must be ASCII; the host must be a hostname or IP address without a port or URL scheme. Passwords are not interpolated. On POSIX, a configuration file containing a password must not grant any group or other permissions (use `chmod 600`). Do not commit secrets or print the environment in CI. On Windows, restrict file access with ACLs.

The default connection uses verified TLS. For a private CA, supply its trusted certificate:

```bash
python add_blocked.py --api-ca-file /path/to/ca.pem --list
```

The certificate must match the configured host. If the host is an IP address, the certificate must contain the corresponding IP SAN. For existing deployments with only the legacy API enabled, explicitly use `--api-plain` (TCP 8728). This transmits credentials without encryption; use only on a trusted, restricted management network. `--insecure` affects HTTPS source downloads only, not RouterOS TLS.

## Usage

```bash
python add_blocked.py example.org example.net 192.0.2.10
python add_blocked.py -A blocked -f domains.txt --dry-run
python add_blocked.py -f https://example.org/domains.txt --resolve-timeout 5
python add_blocked.py --list
python add_blocked.py --delete example.org --dry-run
python add_blocked.py --delete example.org
python add_blocked.py --clean --dry-run
python add_blocked.py --clean --confirm-clean --max-delete 20
```

URLs above are illustrative. Use only trusted sources. Input files contain one entry per line:

```text
# Example entries
example.org
example.net
192.0.2.10
198.51.100.0/24
203.0.113.10-203.0.113.20
```

Blank lines and full-line `#` comments are ignored. Local files use UTF-8 (BOM accepted); HTTP(S) sources use the declared charset or UTF-8. Invalid input aborts before router writes. Names are lowercased, a final DNS dot is removed, internationalized names are converted using Python's built-in IDNA codec, and IPv4 networks are normalized to their network address (a `/32` becomes a single IP). Duplicates are removed while preserving input order. IPv6, URLs as entries, wildcard domains and hosts-file syntax are not supported. The script does not create firewall rules; an existing firewall rule must reference the list to enforce filtering.

Without entries or a file, add/delete mode prompts for a single line of space-separated addresses, including when standard input is redirected. Enter `example.org example.net` to add entries or `-d example.org example.net` to delete them. An empty line exits successfully; end-of-file without input exits with status 1. For example:

```bash
python add_blocked.py
```

An empty file exits successfully without connecting. `--list`, `--delete` and `--clean` are mutually exclusive; listing and cleanup do not accept input entries.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `sites` | — | Positional addresses |
| `-f, --file` | — | Local file or URL |
| `-A, --addr-list` | `blocked` | Target list, ASCII name |
| `-l, --list` | off | Print addresses to stdout |
| `-d, --delete` | off | Remove matching static entries |
| `-c, --clean` | off | Find potentially stale static DNS entries |
| `-C, --dry-run` | off | Preview without router writes |
| `--confirm-clean` | off | Explicitly authorize cleanup writes |
| `--max-delete` | `100` | Maximum rows per delete/cleanup invocation (1–100000) |
| `--bulk-size` | `50` | Delete batch size (1–1000) |
| `--resolve-timeout` | `0` | Local DNS timeout per name, seconds; 0 disables validation |
| `--resolve-workers` | `32` | DNS workers (1–128) |
| `--source-timeout` | `10` | Source socket timeout, seconds |
| `--allow-http` | off | Explicitly allow HTTP sources |
| `--insecure` | off | Disable HTTPS source certificate validation; not recommended |
| `--config` | `add_blocked.conf` | INI file path |
| `--api-timeout` | `10` | RouterOS socket timeout, seconds |
| `--api-port` | `8729` / `8728` | Override TLS / plain API port |
| `--api-plain` | off | Explicitly allow unencrypted RouterOS API |
| `--api-ca-file` | system trust | CA file for RouterOS TLS |
| `--debug` | off | Verbose diagnostic logging |
| `-h, --help` | — | Help |

## Cleanup safety

Cleanup retains the original heuristic: a valid static DNS name is a candidate when no dynamic IPv4 child in the same list has a matching comment. Static IPs, networks, ranges, disabled rows, dynamic rows and unrecognized addresses are protected. Explicit deletion can remove disabled static rows, but skips dynamic rows and returns a nonzero status if any match. The script re-reads the cleanup plan before applying it and aborts if the candidate IDs or addresses have changed.

**A missing dynamic child does not prove a domain is invalid.** Router DNS failures, temporary outages and asynchronous updates can all cause false positives. Always review `--clean --dry-run`, check router DNS health, back up the configuration, and set a suitable `--max-delete` before explicitly authorizing cleanup. The limit counts rows, not distinct names; previews are not truncated. The plan may still change between the final read and a write; the API offers no transaction or rollback for these operations.

## Production operation

- Use verified TLS for both the router and source downloads. HTTP and insecure HTTPS are explicit compatibility options; HTTPS-to-HTTP redirects are rejected. Restrict network egress and trust the input source; URLs are operator-controlled and not suitable for untrusted multi-tenant input.
- Sources are limited to 16 MiB and 100000 input entries; target list processing is limited to 100000 rows. The library can buffer a router reply before the application checks the limit. Keep router lists and feeds within operational limits.
- DNS checks run on the client, not the router, and only when enabled. Each lookup runs in a subprocess with its own timeout. Process startup and system DNS/network behavior may add overhead. Source and API timeouts are socket timeouts, not total job deadlines.
- Serialize jobs targeting the same router/list, including other writers. Idempotency applies to a read snapshot; concurrent writers or router reboots can invalidate it. Use an external lock and execution deadline, for example on Linux with a private writable lock directory:

```bash
flock -n /path/to/private/add_blocked.lock timeout 10m \
  /path/to/.venv/bin/python /path/to/add_blocked.py \
  --config /path/to/add_blocked.conf --file /path/to/domains.txt
```

- Writes stop at the first API error. An error or interrupt can leave earlier changes committed, including part of a deletion batch. No automatic retry or rollback is performed. Re-read the list and reconcile before retrying.
- Listing and dry-run plans use stdout; timestamped diagnostic logs and summaries use stderr. Raw API exceptions, passwords and source URLs are not printed. Address names and IDs may appear in operational logs; protect access and retention accordingly.
- Review dependency updates and security advisories regularly; a pinned version is not a guarantee that it is vulnerability-free.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Successful operation or empty file |
| `1` | Runtime error, DNS skip, matching dynamic row skipped, or deletion limit exceeded |
| `2` | Invalid CLI arguments |
| `130` | Keyboard interrupt |

External wrappers such as `timeout` or `flock` may return additional codes. A DNS skip does not prevent other valid candidates from being added, but the final status is nonzero.

## Testing

```bash
python -m unittest discover -s tests -v
python -m py_compile add_blocked.py tests/test_add_blocked.py
```

The tests use a mock API and a local resolver check for `localhost`; no real router or remote source is needed. They do not establish real RouterOS compatibility. Before using a production list, validate TLS, read/write permissions, additions, batch deletions and cleanup against a disposable test list on the exact deployed RouterOS version.

## References

- [RouterOS API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API)
- [RouterOS Address Lists](https://help.mikrotik.com/docs/spaces/ROS/pages/130220135/Address-lists)
- [RouterOS Services](https://help.mikrotik.com/docs/spaces/ROS/pages/103841820/Services)
- [librouteros 4.2.2](https://librouteros.readthedocs.io/en/4.2.2/)
- [Python ssl](https://docs.python.org/3.10/library/ssl.html) and [subprocess](https://docs.python.org/3.10/library/subprocess.html)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html), [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) and [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
