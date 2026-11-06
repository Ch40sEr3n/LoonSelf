#!/usr/bin/env python3
"""Build a personal Loon profile from verified, official LoonKit releases."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.parse import urlsplit, parse_qsl
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = 'YohakuSama/loonkit'
RAW = 'https://raw.githubusercontent.com/'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def fetch(url):
    require(urlsplit(url).scheme == 'https', 'Only HTTPS downloads are allowed')
    error = None
    for attempt in range(3):
        try:
            headers = {'User-Agent': 'LoonSelf-rule-sync/1.0'}
            if urlsplit(url).hostname == 'api.github.com' and os.environ.get('GH_TOKEN'):
                headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
            request = Request(url, headers=headers)
            with urlopen(request, timeout=45) as response:
                data = response.read(25 * 1024 * 1024 + 1)
            require(len(data) <= 25 * 1024 * 1024, 'Resource exceeds 25 MiB')
            return data
        except Exception as exc:
            error = exc
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError('Download failed: ' + url) from error


def sections(text):
    result = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('[') and line.endswith(']'):
            current = line
            require(current not in result, 'Repeated section: ' + current)
            result[current] = []
        elif current and line and not line.startswith(('#', ';')):
            result[current].append(line)
    return result


def remote(line):
    parts = [p.strip() for p in line.split(',')]
    fields = dict(p.split('=', 1) for p in parts[1:])
    return parts[0], {k.strip(): v.strip() for k, v in fields.items()}


def public_config(text):
    groups = sections(text)
    require(not groups.get('[Proxy]'), 'Public configuration must not contain private nodes')
    require(not groups.get('[Remote Proxy]'), 'Public configuration must not contain node subscriptions')
    require(not re.search(r'\b(?:ss|ssr|vmess|vless|trojan|hysteria2?)://', text, re.I),
            'Private node URI detected')
    for url in re.findall(r'https?://[^\s,\"]+', text):
        parsed = urlsplit(url)
        require(not parsed.username and not parsed.password, 'URL credentials detected')
        require(not any(k.lower() in {'token', 'key', 'apikey', 'api_key', 'password', 'secret', 'auth', 'access_token'}
                        for k, _ in parse_qsl(parsed.query)), 'Secret-looking URL query detected')
    return groups


def native_rules(data):
    result = []
    for raw in data.decode('utf-8-sig').splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        parts = [p.strip() for p in line.split(',')]
        require(len(parts) >= 2 and parts[1], 'Invalid native rule: ' + line[:100])
        kind, value = parts[:2]
        require(kind in {'DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP'},
                'New rule syntax needs review: ' + kind)
        if kind in {'DOMAIN', 'DOMAIN-SUFFIX'}:
            require(len(parts) == 2 and re.fullmatch(r'[A-Za-z0-9_.-]+', value), 'Invalid domain rule')
            require(re.search(r'[A-Za-z0-9_]', value) and not value.startswith('.') and not value.endswith('.'),
                    'Invalid domain boundary')
        elif kind in {'IP-CIDR', 'IP-CIDR6'}:
            ipaddress.ip_network(value, strict=False)
            require(all(p == 'no-resolve' for p in parts[2:]), 'Unexpected IP rule policy')
        elif kind == 'IP-ASN':
            require(value.isdigit(), 'Invalid ASN')
            require(all(p == 'no-resolve' for p in parts[2:]), 'Unexpected ASN rule policy')
        else:
            require(len(parts) == 2 and re.fullmatch(r'[A-Z]{2}', value), 'Invalid GeoIP rule')
        result.append(line)
    require(result, 'Empty rule file')
    return result


def verify_resource(spec, data):
    require(sha(data) == spec['sha256'], 'SHA256 mismatch: ' + spec['path'])
    lines = native_rules(data)
    require(len(lines) == spec['matcher_count'], 'Rule count mismatch: ' + spec['path'])
    return lines


def check_change(old, new, allow_large):
    if old is None or allow_large:
        return
    old_lines, new_lines = set(native_rules(old)), set(native_rules(new))
    changed = len(old_lines ^ new_lines)
    require(changed <= max(20, len(old_lines) * 0.5),
            'Large rule change needs review; inspect changes before using --allow-large-change')


def validate_profile(text, selections=()):
    data = public_config(text)
    known = {'DIRECT', 'REJECT'}
    names = [s.split('=', 1)[0].strip() for s in data['[Proxy Group]']]
    require(len(names) == len(set(names)), 'Duplicate policy group')
    known.update(names)
    filters = {s.split('=', 1)[0].strip() for s in data.get('[Remote Filter]', [])}
    graph = {}
    for line in data['[Proxy Group]']:
        name, body = line.split('=', 1)
        candidates = [p.strip() for p in body.split(',')[1:] if '=' not in p]
        require(all(c in known or c in filters for c in candidates), 'Unknown candidate: ' + name)
        graph[name.strip()] = [c for c in candidates if c in names]
    def visit(name, stack):
        require(name not in stack, 'Policy cycle: ' + name)
        for child in graph[name]:
            visit(child, stack | {name})
    for name in names:
        visit(name, set())
    approved = {choice['filename']: choice for choice in selections}
    for line in data.get('[Remote Rule]', []):
        url, attrs = remote(line)
        choice = approved.get(urlsplit(url).path.rsplit('/', 1)[-1])
        expected_tag = choice.get('display_tag', choice['policy']) if choice else attrs['policy']
        require(attrs['policy'] in known and (choice is None or attrs['policy'] == choice['policy'])
                and attrs['tag'] == expected_tag, 'Remote policy/tag mismatch')
    rules = data.get('[Rule]', [])
    require(rules and rules[-1].startswith('FINAL,'), 'FINAL must be the last local rule')
    for line in rules:
        parts = line.split(',')
        require((parts[1] if parts[0] == 'FINAL' else parts[2]) in known, 'Unknown local policy')


def select_resources(manifest, selections):
    require(manifest['schema_version'] == 2, 'Upstream manifest schema changed')
    require(re.fullmatch(r'v\d+\.\d+\.\d+', manifest['label']), 'Only stable upstream releases are accepted')
    resources = manifest['runtime_resources']
    result = []
    for choice in selections:
        matches = [r for r in resources if r['tag'] == choice['upstream_tag']]
        require(len(matches) == 1, 'Upstream rule renamed, split or missing: ' + choice['upstream_tag'])
        spec = matches[0]
        require(spec['policy'] == choice['policy'] and spec['enabled'] == 'true',
                'Upstream policy changed: ' + choice['upstream_tag'])
        require(re.fullmatch(r'rules/releases/v\d+\.\d+\.\d+/[A-Za-z0-9_-]+\.lsr', spec['path']),
                'Unexpected upstream rule path')
        require(re.fullmatch(r'[0-9a-f]{40}', spec['commit']), 'Rule resource must be commit-pinned')
        require(spec['uri'] == RAW + UPSTREAM + '/' + spec['commit'] + '/' + spec['path'],
                'Unexpected rule origin')
        require(re.fullmatch(r'[A-Za-z0-9_-]+\.lsr', choice['filename']), 'Unsafe local filename')
        result.append((choice, spec))
    require(len({c['filename'] for c, _ in result}) == len(result), 'Duplicate local rule filename')
    return result


def render(base, selected, repository):
    if repository:
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'Invalid GitHub repository')
    data = sections(base)
    existing = data['[Remote Rule]']
    by_name = {choice['filename']: (choice, spec) for choice, spec in selected}
    replacements = {}
    seen = set()
    for line in existing:
        url, attrs = remote(line)
        name = urlsplit(url).path.rsplit('/', 1)[-1]
        if name not in by_name:
            require(not url.startswith(RAW + UPSTREAM + '/'), 'New upstream rule needs a sync-plan entry')
            continue
        choice, spec = by_name[name]
        require(name not in seen, 'Repeated upstream rule in template')
        seen.add(name)
        require(attrs['policy'] == choice['policy'], 'Template rule policy changed')
        address = (RAW + repository + '/main/rules/upstream/' + choice['filename']) if repository else spec['uri']
        replacements[line] = address + ', policy=' + choice['policy'] + ', tag=' + choice.get('display_tag', choice['policy']) + ', enabled=true'
    require(seen == set(by_name), 'Template and sync plan differ')
    lines = [replacements.get(line.strip(), line) for line in base.splitlines()]
    result = '\n'.join(lines) + '\n'
    validate_profile(result, [choice for choice, _ in selected])
    return result


def write_transaction(files):
    before = {name: (ROOT / name).read_bytes() if (ROOT / name).exists() else None for name in files}
    changed = [name for name, data in files.items() if before[name] != data]
    try:
        for name in changed:
            path = ROOT / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
                temp.write(files[name])
                tmp = temp.name
            os.replace(tmp, path)
    except Exception:
        for name in changed:
            path = ROOT / name
            if before[name] is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(before[name])
        raise
    return changed


def check():
    settings = json.loads((ROOT / 'config/sync.json').read_text())
    base = (ROOT / 'config/base.lcf').read_text()
    state = json.loads((ROOT / 'state/upstream.json').read_text())
    validate_profile(base, settings['rules'])
    validate_profile((ROOT / 'LoonKit.lcf').read_text(), settings['rules'])
    selected = [(choice, spec) for choice, spec in zip(settings['rules'], state['resources'])]
    require(len(selected) == len(settings['rules']) == len(state['resources']), 'Incomplete lock file')
    for choice, spec in selected:
        require(choice['upstream_tag'] == spec['tag'] and choice['policy'] == spec['policy'], 'Lock policy mismatch')
        verify_resource(spec, (ROOT / 'rules/upstream' / choice['filename']).read_bytes())
    expected = render(base, selected, state['repository'])
    require((ROOT / 'LoonKit.lcf').read_text() == expected, 'Generated profile is stale; run sync')
    for directory in ['config', 'configs', 'rules/custom']:
        for path in (ROOT / directory).rglob('*.lcf'):
            public_config(path.read_text())
    print('Verified: personal policies, rule hashes, rule syntax and generated profile')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify the committed files without network access')
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', ''))
    parser.add_argument('--allow-large-change', action='store_true')
    parser.add_argument('--offline-dir', type=Path, help='Use a previously downloaded audit snapshot')
    args = parser.parse_args()
    if args.check:
        check()
        return
    settings = json.loads((ROOT / 'config/sync.json').read_text())
    base = (ROOT / 'config/base.lcf').read_text()
    validate_profile(base, settings['rules'])
    if args.offline_dir:
        cache = args.offline_dir
        head_file = cache / 'upstream-head.json'
        head = json.loads(head_file.read_text())['sha'] if head_file.exists() else None
        manifest_bytes = (cache / 'upstream-manifest.json').read_bytes()
        profile_bytes = (cache / 'upstream-profile.lcf').read_bytes()
        license_bytes = (cache / 'LICENSE').read_bytes()
        notices = (cache / 'THIRD_PARTY_NOTICES.md').read_bytes()
    else:
        head = json.loads(fetch('https://api.github.com/repos/' + UPSTREAM + '/commits/main'))['sha']
        require(re.fullmatch(r'[0-9a-f]{40}', head), 'Invalid upstream head')
        prefix = RAW + UPSTREAM + '/' + head + '/'
        manifest_bytes, profile_bytes, license_bytes, notices = list(ThreadPoolExecutor(4).map(fetch, [
            prefix + 'build/release_manifest.json', prefix + 'LoonKit.lcf', prefix + 'LICENSE',
            prefix + 'docs/THIRD_PARTY_NOTICES.md']))
    manifest = json.loads(manifest_bytes)
    require(sha(profile_bytes) == manifest['profile_sha256']['LoonKit.lcf'], 'Upstream profile checksum mismatch')
    selected = select_resources(manifest, settings['rules'])
    def load(pair):
        choice, spec = pair
        data = ((args.offline_dir / ('rule-' + Path(spec['path']).name)).read_bytes()
                if args.offline_dir else fetch(spec['uri']))
        verify_resource(spec, data)
        old_path = ROOT / 'rules/upstream' / choice['filename']
        check_change(old_path.read_bytes() if old_path.exists() else None, data, args.allow_large_change)
        return 'rules/upstream/' + choice['filename'], data
    files = dict(ThreadPoolExecutor(6).map(load, selected))
    repository = args.repository or settings.get('repository', '')
    files['LoonKit.lcf'] = render(base, selected, repository).encode()
    state = {'schema_version': 1, 'upstream': UPSTREAM, 'release': manifest['label'],
             'upstream_commit': head, 'manifest_sha256': sha(manifest_bytes), 'repository': repository,
             'resources': [spec for _, spec in selected]}
    files['state/upstream.json'] = json_bytes(state)
    files['state/health.json'] = json_bytes({'successful_check_month': datetime.now(timezone.utc).strftime('%Y-%m')})
    files['LICENSE'] = license_bytes
    files['LICENSES/UPSTREAM_NOTICES.md'] = notices
    for name in ['LICENSE.GPL-2.0', 'LICENSE.MIT-V2FLY', 'LICENSE.WTFPL-FELIXONMARS']:
        files['LICENSES/' + name] = ((args.offline_dir / name).read_bytes() if args.offline_dir
                                    else fetch(prefix + 'rules/' + name))
    changed = write_transaction(files)
    print(json.dumps({'release': manifest['label'], 'rules': len(selected), 'changed': changed}, ensure_ascii=False))
    check()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Update stopped; no unverified files should be published: ' + str(error), file=sys.stderr)
        sys.exit(1)
