import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sync_rules', ROOT / 'scripts/sync_rules.py')
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class SyncTests(unittest.TestCase):
    def test_rejects_corrupted_rule_download(self):
        record = {'path': 'test.lsr', 'sha256': sync.sha(b'DOMAIN,valid.example\n'), 'matcher_count': 1}
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            sync.verify_resource(record, b'DOMAIN,wrong.example\n')

    def test_blocks_private_subscriptions(self):
        for text in ['[Remote Proxy]\nairport = https://example.org/sub/secret\n',
                     '[Proxy]\nnode=ss,example.org,443\n',
                     '[General]\ndoh-server=https://example.org/dns-query?token=private\n']:
            with self.assertRaises(ValueError):
                sync.public_config(text)

    def test_large_removal_requires_manual_review(self):
        old = ''.join('DOMAIN,host%d.example\n' % i for i in range(100)).encode()
        new = b'DOMAIN,host1.example\n'
        with self.assertRaisesRegex(ValueError, 'Large rule change'):
            sync.check_change(old, new, False)
        sync.check_change(old, new, True)

    def test_rule_file_cannot_supply_a_policy(self):
        with self.assertRaises(ValueError):
            sync.native_rules(b'DOMAIN,example.org,DIRECT\n')

    def test_policy_cycle_is_rejected(self):
        text = '[Proxy Group]\nA=select,B\nB=select,A\n[Rule]\nFINAL,A\n'
        with self.assertRaisesRegex(ValueError, 'cycle'):
            sync.validate_profile(text)

    def test_render_preserves_personal_changes_and_custom_rules(self):
        plan = json.loads((ROOT / 'config/sync.json').read_text())
        state = json.loads((ROOT / 'state/upstream.json').read_text())
        pairs = list(zip(plan['rules'], state['resources']))
        base = (ROOT / 'config/base.lcf').read_text()
        custom = 'https://raw.githubusercontent.com/example/LoonSelf/main/rules/custom/mine.lsr, policy=Lumen, tag=Lumen, enabled=true'
        base = base.replace('[Remote Rule]', '[Remote Rule]\n' + custom)
        result = sync.render(base, pairs, 'example/LoonSelf')
        self.assertIn(custom, result)
        self.assertIn('DOMAIN-SUFFIX,lumenvids.com,Lumen', result)
        self.assertIn('DOMAIN-SUFFIX,raw.githubusercontent.com,GitHub', result)
        self.assertEqual(sync.sections(result)['[Rule]'], sync.sections(base)['[Rule]'])
        self.assertEqual(sync.sections(result)['[Proxy Group]'], sync.sections(base)['[Proxy Group]'])
        self.assertNotIn('policy=Claude,', result)
        self.assertIn('/example/LoonSelf/main/rules/upstream/ChatGPT.lsr', result)

    def test_upstream_policy_changes_stop_update(self):
        plan = json.loads((ROOT / 'config/sync.json').read_text())
        state = json.loads((ROOT / 'state/upstream.json').read_text())
        resources = json.loads(json.dumps(state['resources']))
        resources[0]['policy'] = 'Unexpected'
        with self.assertRaisesRegex(ValueError, 'policy changed'):
            sync.select_resources({'schema_version': 2, 'label': 'v7.0.10', 'runtime_resources': resources}, plan['rules'])

    def test_missing_rule_does_not_restore_deleted_services(self):
        plan = json.loads((ROOT / 'config/sync.json').read_text())
        state = json.loads((ROOT / 'state/upstream.json').read_text())
        with self.assertRaisesRegex(ValueError, 'missing'):
            sync.select_resources({'schema_version': 2, 'label': 'v7.0.10', 'runtime_resources': state['resources'][1:]}, plan['rules'])


if __name__ == '__main__':
    unittest.main()
