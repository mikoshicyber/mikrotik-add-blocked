#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import argparse
import configparser
import socket
import time
import ssl
import ipaddress
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from librouteros import connect

def eprint(debug, *args, **kwargs):
    if debug:
        print(*args, file=sys.stderr, **kwargs)

def get_credentials(config_file='add_blocked.conf', debug=False):
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
        user = config.get('credentials', 'user', fallback='blckd')
        password = config.get('credentials', 'password', fallback='blckd')
        host = config.get('credentials', 'host', fallback='192.168.88.1')
        eprint(debug, f'Используемые учетные данные: user={user}, host={host}')
    except Exception as e:
        eprint(debug, f'Ошибка при чтении файла конфигурации: {e}')
        user, password, host = 'blckd', 'blckd', '192.168.88.1'
    return user, password, host

def normalize_domain(d):
    return (d or '').strip().lower().rstrip('.')

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def load_blocked_entries(api, list_name, debug=False):
    try:
        rows = list(api(cmd='/ip/firewall/address-list/print'))
    except Exception as e:
        eprint(debug, f'Ошибка при чтении address-list: {e}')
        return set(), {}, []
    addr_to_ids = {}
    for r in rows:
        if r.get('list') != list_name:
            continue
        a = normalize_domain(r.get('address') or '')
        rid = r.get('.id')
        if a and rid:
            addr_to_ids.setdefault(a, []).append(rid)
    s = set(addr_to_ids.keys())
    eprint(debug, f'Загружено {len(s)} записей из списка {list_name}')
    return s, addr_to_ids, rows

def load_dynamic_dns_comments(api, debug=False):
    try:
        rows = list(api(cmd='/ip/dns/static/print'))
    except Exception as e:
        eprint(debug, f'Ошибка при чтении /ip/dns/static: {e}')
        return set()
    out = set()
    for r in rows:
        dyn = r.get('dynamic')
        dyn = (dyn is True) or (isinstance(dyn, str) and dyn.lower() in ('true', 'yes', '1'))
        if not dyn:
            continue
        c = normalize_domain(r.get('comment') or '')
        if c:
            out.add(c)
    eprint(debug, f'Найдено {len(out)} динамических DNS-комментариев')
    return out

def _resolve_task(domain):
    try:
        socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        return True
    except Exception:
        return False

def bulk_resolve(domains, per_domain_timeout, workers, debug=False):
    if per_domain_timeout is None or per_domain_timeout <= 0:
        return {d: True for d in domains}
    res = {d: False for d in domains}
    start = time.time()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        fut_map = {ex.submit(_resolve_task, d): d for d in domains}
        pending = set(fut_map.keys())
        deadline = time.time() + per_domain_timeout
        while pending:
            remaining = max(0.0, deadline - time.time())
            if remaining == 0:
                break
            done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            for fut in done:
                d = fut_map[fut]
                try:
                    res[d] = bool(fut.result())
                except Exception:
                    res[d] = False
        for fut in pending:
            fut.cancel()
    dur = time.time() - start
    eprint(debug, f'Резолвинг {len(domains)} доменов за {dur:.3f}s, таймаут {per_domain_timeout}s')
    return res

def add_sites_after_resolve(api, sites, existing, list_name, dry, resolve_timeout, resolve_workers, debug=False):
    normalized = [normalize_domain(s) for s in sites if normalize_domain(s)]
    candidates = [s for s in normalized if s not in existing]
    if resolve_timeout > 0:
        resolved_map = bulk_resolve(set(candidates), resolve_timeout, resolve_workers, debug)
    else:
        resolved_map = {s: True for s in candidates}
    idx = 0
    for s in normalized:
        idx += 1
        if s in existing:
            eprint(debug, f'[{idx}] Уже есть: {s}')
            continue
        ok = resolved_map.get(s, False)
        if not ok:
            print(f'SKIP: {s} не резолвится за {resolve_timeout}s')
            continue
        if dry:
            print(f'DRY-RUN: добавил бы {s}')
            existing.add(s)
            continue
        try:
            resp = list(api(cmd='/ip/firewall/address-list/add', **{'list': list_name, 'address': s}))
            eprint(debug, f'[{idx}] add: {resp}')
            existing.add(s)
        except Exception as e:
            eprint(debug, f'[{idx}] Ошибка добавления {s}: {e}')

def batched_ids(ids, size):
    batch = []
    for i in ids:
        batch.append(i)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch

def remove_sites(api, sites, addr_to_ids, dry, bulk_size, debug=False):
    for idx, site in enumerate(sites, start=1):
        s = normalize_domain(site)
        ids = addr_to_ids.get(s, [])
        if not ids:
            eprint(debug, f'[{idx}] Нет: {s}')
            continue
        for b in batched_ids(ids, max(1, bulk_size)):
            if dry:
                print(f'DRY-RUN: удалил бы {s} ids={b}')
                continue
            try:
                resp = list(api(cmd='/ip/firewall/address-list/remove', numbers=",".join(b)))
                eprint(debug, f'[{idx}] remove {s} ids={b}: {resp}')
            except Exception as e:
                eprint(debug, f'[{idx}] Ошибка удаления {s} ids={b}: {e}')

def list_sites(api, list_name, debug=False):
    try:
        rows = list(api(cmd='/ip/firewall/address-list/print'))
        for r in rows:
            if r.get('list') == list_name:
                print(r.get('address'))
    except Exception as e:
        eprint(debug, f'Ошибка чтения списка: {e}')

def _split_lines_to_domains(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        out.append(s)
    return out

def read_sites_from_source(source, insecure=False, timeout=10, debug=False):
    if not source:
        return []
    parsed = urlparse(source)
    if parsed.scheme in ('http', 'https'):
        try:
            ctx = None
            if parsed.scheme == 'https' and insecure:
                ctx = ssl._create_unverified_context()
            req = Request(source, headers={'User-Agent': 'addrlist-tool/1.0'})
            with urlopen(req, timeout=timeout, context=ctx) as resp:
                charset = resp.headers.get_content_charset() or 'utf-8'
                body = resp.read().decode(charset, errors='replace')
            items = _split_lines_to_domains(body)
            eprint(debug, f'Загружено по URL {source}: {len(items)} доменов')
            return items
        except Exception as e:
            eprint(debug, f'Ошибка загрузки URL {source}: {e}')
            return []
    try:
        with open(source, 'r', encoding='utf-8') as f:
            items = _split_lines_to_domains(f.read())
        eprint(debug, f'Загружено из файла {source}: {len(items)} доменов')
        return items
    except Exception as e:
        eprint(debug, f'Ошибка чтения файла {source}: {e}')
        return []

def clean_sites(api, list_name, dry, bulk_size, debug=False):
    blocked, addr_to_ids, all_rows = load_blocked_entries(api, list_name, debug)
    domain_ids = {d: ids for d, ids in addr_to_ids.items() if not is_ip(d)}
    dyn_rows = []
    for r in all_rows:
        if r.get('list') != list_name:
            continue
        dyn = r.get('dynamic')
        dyn = (dyn is True) or (isinstance(dyn, str) and dyn.lower() in ('true', 'yes', '1'))
        if not dyn:
            continue
        addr = normalize_domain(r.get('address') or '')
        if is_ip(addr):
            dyn_rows.append(r)
    dyn_comments = {normalize_domain(r.get('comment') or '') for r in dyn_rows if r.get('comment')}
    keep_domains = {d for d in domain_ids.keys() if d in dyn_comments}
    rm_domains = sorted(set(domain_ids.keys()) - keep_domains)
    eprint(debug, f'К удалению доменов: {len(rm_domains)}')
    if not rm_domains:
        return 0
    removed = 0
    for i, d in enumerate(rm_domains, start=1):
        ids = domain_ids.get(d, [])
        for b in batched_ids(ids, max(1, bulk_size)):
            if dry:
                print(f'DRY-RUN: удалил бы {d} ids={b}')
                removed += len(b)
                continue
            try:
                resp = list(api(cmd='/ip/firewall/address-list/remove', numbers=",".join(b)))
                eprint(debug, f'[clean {i}] remove {d} ids={b}: {resp}')
                removed += len(b)
            except Exception as e:
                eprint(debug, f'[clean {i}] Ошибка удаления {d} ids={b}: {e}')
    return removed

def main():
    p = argparse.ArgumentParser(description='MikroTik address-list tool')
    p.add_argument('sites', nargs='*')
    p.add_argument('-f', '--file', help='Путь к файлу или URL со списком доменов')
    p.add_argument('--source-timeout', type=float, default=10.0)
    p.add_argument('--insecure', action='store_true')
    p.add_argument('-d', '--delete', action='store_true')
    p.add_argument('-l', '--list', action='store_true')
    p.add_argument('-c', '--clean', action='store_true')
    p.add_argument('-A', '--addr-list', default='blocked')
    p.add_argument('-C', '--dry-run', action='store_true')
    p.add_argument('--bulk-size', type=int, default=50)
    p.add_argument('--resolve-timeout', type=float, default=0.0)
    p.add_argument('--resolve-workers', type=int, default=32)
    p.add_argument('--debug', action='store_true')
    a = p.parse_args()

    if a.file:
        a.sites.extend(read_sites_from_source(a.file, insecure=a.insecure, timeout=a.source_timeout, debug=a.debug))

    if not a.sites and not a.list and not a.clean:
        inp = input('Введите домены. Для удаления добавьте -d.\n').split()
        if '-d' in inp:
            a.delete = True
            inp.remove('-d')
        a.sites = inp

    user, pw, host = get_credentials(debug=a.debug)
    try:
        api = connect(host=host, username=user, password=pw)
        eprint(a.debug, f'Подключён к {host}')
    except Exception as e:
        eprint(a.debug, f'Ошибка подключения: {e}')
        sys.exit(1)

    if a.list:
        list_sites(api, a.addr_list, a.debug)
        api.close()
        return

    if a.clean:
        cnt = clean_sites(api, a.addr_list, a.dry_run, a.bulk_size, a.debug)
        print(f'Удалено (или было бы удалено в dry-run): {cnt}')
        api.close()
        return

    blocked, m, _ = load_blocked_entries(api, a.addr_list, a.debug)

    if a.delete:
        remove_sites(api, a.sites, m, a.dry_run, a.bulk_size, a.debug)
    else:
        add_sites_after_resolve(api, a.sites, blocked, a.addr_list, a.dry_run, a.resolve_timeout, a.resolve_workers, a.debug)

    api.close()

if __name__ == '__main__':
    main()
