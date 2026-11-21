import copy
import json
import unittest
from pathlib import Path
from scripts.build import generate

CFG = json.loads((Path(__file__).resolve().parents[1] / 'personal/settings.json').read_text())
FIXTURE = r'''# Johnshall
[General]
dns-server = https://doh.pub/dns-query
bypass-system = true
[Rule]
DOMAIN-SUFFIX,telegram.org,Proxy
IP-CIDR,91.108.56.0/22,Proxy
IP-CIDR,18.194.0.0/15,Proxy
DOMAIN-SUFFIX,ads.example.com,Reject
GEOIP,CN,DIRECT
FINAL,proxy
[URL Rewrite]
^https?://(www.)?(g|google)\.cn https://www.google.com 302
[MITM]
hostname = *.google.cn,*.googlevideo.com
'''

class TestBuild(unittest.TestCase):
    def run_build(self, text=FIXTURE, cfg=None, priority=None, domestic=None, hosts=None):
        return generate(text, cfg or copy.deepcopy(CFG), priority or [], domestic or [], hosts or [], min_rules=1)[0]

    def test_configuration_and_order(self):
        s = self.run_build(priority=['DOMAIN,ads.example.com,DIRECT'], domestic=['DOMAIN-SUFFIX,qq.com,DIRECT'])
        self.assertIn('dns-server = https://8.8.8.8/dns-query#proxy,https://1.1.1.1/dns-query#proxy\n', s)
        self.assertIn('fallback-dns-server = https://223.5.5.5/dns-query,https://223.6.6.6/dns-query\n', s)
        self.assertIn('direct-dns-server = https://223.5.5.5/dns-query,https://1.12.12.12/dns-query\n', s)
        self.assertIn('include = default.conf\n', s)
        self.assertIn('update-url = https://raw.githubusercontent.com/TBOsec/Shadowrocket-ADBlock-Rules-Forever/personal/dist/sr_personal.conf\n', s)
        self.assertNotIn('dns-server = https://doh.pub', s)
        self.assertIn('bypass-system = true', s)
        self.assertIn('91.108.56.0/22,Proxy,no-resolve', s)
        self.assertIn('18.194.0.0/15,Proxy\n', s)
        self.assertLess(s.index('DOMAIN,ads.example.com,DIRECT'), s.index('DOMAIN-SUFFIX,ads.example.com,Reject'))
        self.assertLess(s.index('DOMAIN-SUFFIX,ads.example.com,Reject'), s.index('DOMAIN-SUFFIX,qq.com,DIRECT'))
        self.assertLess(s.index('DOMAIN-SUFFIX,qq.com,DIRECT'), s.index('GEOIP,CN,DIRECT'))
        self.assertIn('[URL Rewrite]', s)
        self.assertIn('https://www.google.com 302', s)
        self.assertIn('[MITM]\nhostname = *.google.cn,*.googlevideo.com\nenable = true\nca-passphrase =\nca-p12 =\n', s)
        self.assertNotIn('ChinaMaxNoIP.list', s)

    def test_optional_switches(self):
        cfg = copy.deepcopy(CFG)
        cfg.update(telegram_no_resolve=False, remove_google_rewrite_and_mitm=False, enable_china_max_no_ip=True, force_hk_mo_tw_suffix_proxy=True)
        s = self.run_build(cfg=cfg, hosts=['ads.example.com = 0.0.0.0'])
        self.assertIn('[MITM]', s)
        self.assertIn('[Host]', s)
        self.assertIn('ChinaMaxNoIP.list,DIRECT', s)
        self.assertIn('DOMAIN-SUFFIX,hk,PROXY', s)
        self.assertNotIn('no-resolve', s)

    def test_bad_upstream(self):
        for text in [FIXTURE.replace('FINAL,proxy', 'FINAL,DIRECT'), FIXTURE.replace('GEOIP,CN,DIRECT',''), FIXTURE.replace('[MITM]', '[Other]'), '<html>error</html>']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.run_build(text=text)

    def test_mitm_removal_still_checks_upstream_content(self):
        cfg = {**CFG, 'remove_google_rewrite_and_mitm': True, 'enable_mitm': False}
        result = self.run_build(cfg=cfg)
        self.assertNotIn('[MITM]', result)
        self.assertNotIn('[URL Rewrite]', result)
        changed = FIXTURE.replace('hostname = *.google.cn,*.googlevideo.com', 'hostname = *.bank.example')
        with self.assertRaisesRegex(ValueError, 'new MITM content'):
            self.run_build(text=changed, cfg=cfg)

    def test_mitm_credentials_stay_blank(self):
        text = FIXTURE + 'ca-passphrase = sample-password\nCA-P12 = sample-certificate\nenable = false\n'
        result = self.run_build(text=text)
        self.assertIn('ca-passphrase =\nca-p12 =\nenable = true\n', result)
        self.assertNotIn('sample-password', result)
        self.assertNotIn('sample-certificate', result)

    def test_invalid_custom_rule(self):
        with self.assertRaises(ValueError):
            self.run_build(priority=['FINAL,DIRECT'])

    def test_deterministic(self):
        self.assertEqual(self.run_build(), self.run_build())

if __name__ == '__main__':
    unittest.main()
