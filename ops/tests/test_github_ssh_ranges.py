import ipaddress
import json
import unittest
from unittest.mock import patch

from ops.github_ssh_ranges import extract_ranges, parse_meta, render_policy


BASE = '''# Preserve this locally pinned policy comment verbatim.
table inet monitor_ssh_geo {
    set kr4 {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 8.8.8.0/24 }
    }
    set kr6 {
        type ipv6_addr
        flags interval
        auto-merge
        elements = { 2001:4860::/32 }
    }
    counter ssh_geo_loopback { }
    counter ssh_geo_lan { }
    counter ssh_geo_kr4 { }
    counter ssh_geo_kr6 { }
    counter ssh_geo_denied { }
    chain input {
        type filter hook input priority -10; policy accept;
        iifname "lo" tcp dport { 22, 22022 } counter name ssh_geo_loopback return
        iifname "eth0" ip saddr 192.168.75.190 tcp dport { 22, 22022 } counter name ssh_geo_lan return
        ip saddr @kr4 tcp dport { 22, 22022 } counter name ssh_geo_kr4 return
        ip6 saddr @kr6 tcp dport { 22, 22022 } counter name ssh_geo_kr6 return
        tcp dport { 22, 22022 } limit rate 3/minute burst 5 packets log prefix "SSH_GEO_DROP " level info
        tcp dport { 22, 22022 } counter name ssh_geo_denied drop
    }
}
'''
EMPTY = {4: [], 6: []}
RANGES = {4: ["20.118.29.0/24"], 6: ["2606:50c0::/32"]}


def payload(**fields):
    return json.dumps({"actions": ["20.118.29.0/24", "2606:50c0::/32"], **fields}).encode()


class GithubMetaTests(unittest.TestCase):
    def test_all_published_categories_and_future_ip_arrays_are_included(self):
        fields = {name: [f"11.0.{index}.0/24"] for index, name in enumerate((
            "actions_macos", "api", "codespaces", "copilot", "dependabot", "git",
            "github_enterprise_importer", "hooks", "importer", "packages", "pages",
            "web", "future_published_service"))}
        fields.update(ssh_keys=["ssh-ed25519 non-IP-key"], commit_signing_keys=["key"],
                      domains={"actions": ["*.actions.githubusercontent.com"]},
                      verifiable_password_authentication=False,
                      ssh_key_fingerprints={"SHA256_RSA": "fingerprint"})
        result = parse_meta(payload(**fields))
        actual = [ipaddress.ip_network(value) for value in result[4]]
        for values in list(fields.values())[:13]:
            self.assertTrue(any(ipaddress.ip_network(values[0]).subnet_of(net) for net in actual))
        self.assertIn("20.118.29.0/24", result[4])
        self.assertEqual(result[6], RANGES[6])

    def test_collapse_preserves_exact_address_union_and_gaps(self):
        source = ["20.118.28.0/25", "20.118.28.128/25", "20.118.28.0/26",
                  "20.118.30.0/24", "20.118.28.0/25", "2606:50C0::/33", "2606:50c0:8000::/33"]
        result = parse_meta(payload(actions=source))
        self.assertEqual(result, {4: ["20.118.28.0/24", "20.118.30.0/24"], 6: RANGES[6]})
        self.assertFalse(any(ipaddress.ip_address("20.118.29.96") in ipaddress.ip_network(net)
                             for net in result[4]))

    def test_malformed_and_missing_metadata_fail_closed(self):
        cases = [b"", b"{", b"\xff", b"null", b"[]", b"{}", b'{"actions": []}',
                 payload(actions=None), payload(actions="20.118.29.0/24"),
                 payload(actions=["20.118.29.0/24"]), payload(actions=["2606:50c0::/32"]),
                 payload(api="20.118.29.0/24"), payload(new_service=["not-an-IP"]),
                 payload(actions=[None]), payload(actions=[123]),
                 b'{"actions":[],"actions":["20.118.29.0/24","2606:50c0::/32"]}']
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                parse_meta(data)

    def test_nonpublic_default_routes_and_command_injection_fail_closed(self):
        bad = ["0.0.0.0/0", "::/0", "10.0.0.0/8", "127.0.0.1/32", "100.64.0.0/10",
               "169.254.0.0/16", "192.0.2.0/24", "198.18.0.0/15", "224.0.0.0/4",
               "240.0.0.0/4", "8.0.0.0/6", "192.0.0.0/8", "fc00::/7", "fe80::/10",
               "2001:db8::/32", "2001::/23", "2002::/16", "3fff::/20", "4000::/3",
               "::ffff:8.8.8.8/128", "20.118.29.96/24", "20.118.29.96", "20.1.1.0/255.255.255.0",
               "20.118.29.0/24; accept", "20.118.29.0/24\nflush ruleset"]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_meta(payload(web=[value]))

    def test_byte_and_range_bounds_count_duplicates_before_collapse(self):
        with patch("ops.github_ssh_ranges.MAX_META_BYTES", 2), self.assertRaises(ValueError):
            parse_meta(payload())
        with patch("ops.github_ssh_ranges.MAX_META_RANGES", 3), self.assertRaises(ValueError):
            parse_meta(payload(api=["20.118.29.0/24"] * 2))
        with self.assertRaises(ValueError):
            parse_meta("not bytes")


class GithubPolicyTests(unittest.TestCase):
    def test_managed_policy_preserves_every_baseline_byte(self):
        result = render_policy(BASE, RANGES)
        self.assertEqual(render_policy(result, EMPTY), BASE)
        self.assertEqual(extract_ranges(result), RANGES)
        self.assertEqual(extract_ranges(BASE), EMPTY)
        self.assertIn("counter ssh_geo_github4 { }", result)
        self.assertIn("counter ssh_geo_github6 { }", result)
        for version, family in ((4, "ip"), (6, "ip6")):
            rule = (f"{family} saddr @github{version} tcp dport {{ 22, 22022 }} "
                    f"counter name ssh_geo_github{version} return")
            self.assertIn(rule, result)
            self.assertLess(result.index(rule), result.index('log prefix "SSH_GEO_DROP "'))
            self.assertGreater(result.index(rule), result.index("counter name ssh_geo_kr6 return"))
        self.assertEqual(result.count("hook input"), 1)

    def test_updates_are_idempotent_and_remove_retired_ranges(self):
        before = render_policy(BASE, RANGES)
        self.assertEqual(render_policy(before, RANGES), before)
        updated = {4: ["20.118.30.0/24"], 6: ["2606:50c1::/32"]}
        after = render_policy(before, updated)
        self.assertEqual(after, render_policy(BASE, updated))
        self.assertNotIn("20.118.29.0/24", after)
        self.assertNotIn("2606:50c0::/32", after)
        self.assertEqual(render_policy(after, EMPTY), BASE)

    def test_offline_country_refresh_preserves_pinned_github_coverage(self):
        previous = render_policy(BASE, RANGES)
        new_base = BASE.replace("8.8.8.0/24", "8.8.0.0/16")
        refreshed = render_policy(new_base, extract_ranges(previous))
        self.assertEqual(extract_ranges(refreshed), RANGES)
        self.assertEqual(render_policy(refreshed, EMPTY), new_base)

    def test_range_input_is_independently_validated(self):
        bad = [{}, {4: RANGES[4]}, {4: RANGES[4], 6: []},
               {4: ["10.0.0.0/8"], 6: RANGES[6]},
               {4: RANGES[6], 6: RANGES[4]},
               {4: ["20.118.29.0/24\naccept"], 6: RANGES[6]},
               {4: "20.118.29.0/24", 6: RANGES[6]}]
        for ranges in bad:
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                render_policy(BASE, ranges)

    def test_ambiguous_modified_or_out_of_scope_policy_is_rejected(self):
        rendered = render_policy(BASE, RANGES)
        cases = [BASE.replace("monitor_ssh_geo", "another_table"), "flush ruleset\n" + BASE,
                 BASE + "table inet another_table {}\n", BASE + "delete table inet something\n",
                 BASE.replace("    chain input {", "    chain input {\n    chain another {"),
                 BASE.replace('log prefix "SSH_GEO_DROP "', 'log prefix "different "'),
                 BASE.replace("counter name ssh_geo_denied drop", "counter name ssh_geo_denied accept"),
                 BASE.replace("    set kr4", "    set github4"),
                 rendered.replace("# END GITHUB SSH SETS", "# MISSING END"),
                 rendered + "# BEGIN GITHUB SSH SETS\n",
                 rendered.replace("counter name ssh_geo_github4 return", "counter name ssh_geo_github4 accept"),
                 rendered.replace("20.118.29.0/24", "0.0.0.0/0"),
                 rendered.replace("    # BEGIN GITHUB SSH SETS", "# BEGIN GITHUB SSH SETS"),
                 rendered.replace("        # END GITHUB SSH RULES\n", "        # END GITHUB SSH RULES\n\n")]
        for policy in cases:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                render_policy(policy, RANGES)

    def test_rendered_output_and_input_count_are_bounded(self):
        with patch("ops.github_ssh_ranges.MAX_POLICY_BYTES", len(BASE)), self.assertRaises(ValueError):
            render_policy(BASE, RANGES)
        with patch("ops.github_ssh_ranges.MAX_META_RANGES", 1), self.assertRaises(ValueError):
            render_policy(BASE, RANGES)


if __name__ == "__main__":
    unittest.main()
