#!/usr/bin/env python3
"""Generate a personal Shadowrocket config without executing upstream code."""
import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = 'https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip_ad.conf'
CHINA = 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/ChinaMaxNoIP/ChinaMaxNoIP.list'
OUT = ROOT / 'dist' / 'sr_personal.conf'
TG = set('91.108.56.0/22 91.108.4.0/22 91.108.8.0/22 91.108.16.0/22 91.108.12.0/22 149.154.160.0/20 91.105.192.0/23 91.108.20.0/22 185.76.151.0/24 2001:b28:f23d::/48 2001:b28:f23f::/48 2001:67c:4e8::/48 2001:b28:f23c::/48 2a0a:f280::/32'.split())
HEADER = re.compile(r'^\s*\[([^\]]+)\]\s*$')


def active(line):
    return bool(line.strip()) and not line.lstrip().startswith(('#', ';', '//'))


def rule_parts(line):
    # '#' in DNS URLs belongs to the value; only strip spaced inline comments here.
    return [p.strip() for p in re.split(r'\s+#', line, maxsplit=1)[0].split(',')]


def read_custom(path):
    return [x.strip() for x in path.read_text(encoding='utf-8').splitlines() if active(x)]


def parse(text):
    preamble, sections = [], []
    dest = preamble
    for line in text.splitlines():
        match = HEADER.fullmatch(line)
        if match:
            key = match.group(1)
            if any(k.lower() == key.lower() for k, _ in sections):
                raise ValueError(f'duplicate section {key}')
            dest = []
            sections.append((key, dest))
        else:
            dest.append(line)
    return preamble, sections


def replace_settings(lines, changes):
    out, seen = [], set()
    lookup = {k.lower(): (k, v) for k, v in changes.items()}
    for line in lines:
        key = line.split('=', 1)[0].strip().lower() if active(line) and '=' in line else ''
        if key not in lookup:
            out.append(line)
        elif key not in seen:
            k, v = lookup[key]
            out.append(f'{k} = {v}'.rstrip())
            seen.add(key)
    for key, (k, v) in lookup.items():
        if key not in seen:
            out.append(f'{k} = {v}'.rstrip())
    return out


def validate_custom(rules, direct_only=False):
    seen = set()
    for line in rules:
        p = rule_parts(line)
        if len(p) != 3 or p[0].upper() not in {'DOMAIN', 'DOMAIN-SUFFIX'} or not re.fullmatch(r'[a-zA-Z0-9.-]+', p[1]):
            raise ValueError(f'unsupported personal domain rule: {line}')
        if p[2].upper() not in ({'DIRECT'} if direct_only else {'DIRECT', 'PROXY', 'REJECT'}):
            raise ValueError(f'invalid personal policy: {line}')
        k = (p[0].upper(), p[1].lower())
        if k in seen:
            raise ValueError(f'duplicate personal rule: {line}')
        seen.add(k)


def generate(text, cfg, priority, domestic, hosts, min_rules=10000):
    preamble, sections = parse(text)
    by_name = {k.lower(): v for k, v in sections}
    if not {'general', 'rule'} <= by_name.keys() or any(active(l) for l in preamble):
        raise ValueError('unexpected upstream format')
    if 'Johnshall' not in text[:2000]:
        raise ValueError('upstream attribution missing')
    original = by_name['rule']
    rules = [(i, rule_parts(l)) for i, l in enumerate(original) if active(l)]
    if len(rules) < min_rules:
        raise ValueError(f'upstream rules too few: {len(rules)}')
    geo = [i for i, p in rules if [x.upper() for x in p] == ['GEOIP', 'CN', 'DIRECT']]
    final = [(i, p) for i, p in rules if p[0].upper() == 'FINAL']
    if len(geo) != 1 or len(final) != 1 or [x.upper() for x in final[0][1]] != ['FINAL', 'PROXY'] or geo[0] >= final[0][0] or final[0][0] != rules[-1][0]:
        raise ValueError('GEOIP/FINAL structure changed; review upstream')
    if not any(len(p) >= 3 and p[2].upper().startswith('REJECT') for _, p in rules):
        raise ValueError('ad blocking missing')
    validate_custom(priority)
    validate_custom(domestic, direct_only=True)
    for host in hosts:
        if '=' not in host or not re.fullmatch(r'[A-Za-z0-9.-]+', host.split('=', 1)[0].strip()):
            raise ValueError(f'invalid host: {host}')
    general = cfg['general']
    if any(not isinstance(v, str) or '\n' in v or '\r' in v for v in general.values()):
        raise ValueError('general values must be single-line strings')
    by_name['general'][:] = replace_settings(by_name['general'], general)
    modified, patched = [], 0
    for i, line in enumerate(original):
        if i == geo[0]:
            modified.extend(['', '# Personal fallback domain rules (after upstream)'])
            if cfg.get('force_hk_mo_tw_suffix_proxy'):
                modified.extend(f'DOMAIN-SUFFIX,{t},PROXY' for t in ('hk', 'mo', 'tw'))
            modified.extend(domestic)
            if cfg.get('enable_china_max_no_ip'):
                modified.append(f'RULE-SET,{CHINA},DIRECT')
            modified.append('')
        p = rule_parts(line)
        if cfg.get('telegram_no_resolve') and active(line) and len(p) == 3 and p[0].upper() in {'IP-CIDR', 'IP-CIDR6'} and p[1] in TG and p[2].upper() == 'PROXY':
            line = re.sub(r'(\s+#.*)$', r',no-resolve\1', line) if re.search(r'\s+#', line) else line.rstrip() + ',no-resolve'
            patched += 1
        modified.append(line)
    by_name['rule'][:] = ['# Personal priority exceptions'] + priority + [''] + modified
    if hosts:
        if 'host' not in by_name:
            sections.append(('Host', hosts.copy()))
        else:
            existing = {h.split('=', 1)[0].strip().lower() for h in by_name['host'] if active(h) and '=' in h}
            if any(h.split('=', 1)[0].strip().lower() in existing for h in hosts):
                raise ValueError('Host collision; review')
            by_name['host'].extend(hosts)
    if cfg.get('remove_google_rewrite_and_mitm'):
        # Only remove the exact currently reviewed upstream content; fail on new entries.
        expected = {'url rewrite': r'^https?://(www.)?(g|google)\.cn https://www.google.com 302', 'mitm': 'hostname = *.google.cn,*.googlevideo.com'}
        for name, lines in sections:
            if name.lower() in expected and any(l.strip() != expected[name.lower()] for l in lines if active(l)):
                raise ValueError(f'new {name} content; review before removal')
        sections = [(k, v) for k, v in sections if k.lower() not in expected]
    elif cfg.get('enable_mitm'):
        if not {'url rewrite', 'mitm'} <= by_name.keys():
            raise ValueError('upstream rewrite or MITM section missing')
        by_name['mitm'][:] = replace_settings(by_name['mitm'], {
            'enable': 'true',
            'ca-passphrase': '',
            'ca-p12': '',
        })
    header = preamble + [f'# Modified personal configuration; source: {UPSTREAM}', '# Upstream: Moshel and Johnshall; derivative: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)', f'# Upstream active rule count: {len(rules)}', f'# Telegram IP rules patched: {patched}']
    result = '\n'.join(header + [line for k, v in sections for line in [f'[{k}]', *v]]) + '\n'
    return result, len(rules), patched


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream-file', type=Path, help='optional locally saved upstream config')
    parser.add_argument('--allow-large-drop', action='store_true', help='manual override after reviewing rule count')
    args = parser.parse_args()
    if args.upstream_file:
        raw = args.upstream_file.read_bytes()
    else:
        req = urllib.request.Request(UPSTREAM, headers={'User-Agent': 'Shadowrocket-Personal-Builder/1.0'})
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('upstream exceeds 16 MiB')
    cfg = json.loads((ROOT/'personal/settings.json').read_text(encoding='utf-8'))
    result, count, patched = generate(raw.decode('utf-8-sig'), cfg, *(read_custom(ROOT/'personal'/f) for f in ('priority.rules','china-domain.rules','host.rules')))
    if OUT.exists():
        old = re.search(r'^# Upstream active rule count: (\d+)\s*$', OUT.read_text(encoding='utf-8'), re.M)
        if not old:
            raise ValueError('previous output metadata missing; review before replacing')
        if count < int(old.group(1)) * 0.8 and not args.allow_large_drop:
            raise ValueError('upstream rule count dropped >20%; review before publishing')
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix('.tmp')
    tmp.write_text(result, encoding='utf-8')
    tmp.replace(OUT)
    print(f'Generated {OUT.relative_to(ROOT)}: {count} upstream rules, {patched} Telegram IP rules patched')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f'Build aborted: {e}', file=sys.stderr)
        sys.exit(1)
