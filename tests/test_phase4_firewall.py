import unittest
from unittest.mock import patch

from src.network_firewall import (
    FirewallError,
    FirewallOwnershipError,
    NftablesBackend,
    normalize_ip,
    TABLE_FAMILY,
    TABLE_NAME,
)


class FirewallAddressTests(unittest.TestCase):
    def test_accepts_single_unicast_addresses(self):
        self.assertEqual(normalize_ip("8.8.8.8"), "8.8.8.8")
        self.assertEqual(
            normalize_ip("2606:4700:4700::1111"),
            "2606:4700:4700::1111",
        )

    def test_rejects_invalid_or_unsafe_addresses(self):
        invalid = (
            "",
            "not-an-ip",
            "192.0.2.1/24",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "224.0.0.1",
            "169.254.1.2",
            "ff02::1",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_ip(value)


class NftablesInspectionTests(unittest.TestCase):
    def setUp(self):
        # No real nft executable or privileged firewall access is needed.
        self.backend = NftablesBackend(executable="/fake/nft")

    def test_missing_table_is_reported_without_creating_it(self):
        with patch.object(self.backend, "_run", return_value="") as run:
            self.assertIsNone(self.backend._table())

        run.assert_called_once_with("list", "tables")

    def test_existing_table_is_inspected(self):
        table_list = f"table {TABLE_FAMILY} {TABLE_NAME}"
        table_body = f'table {TABLE_FAMILY} {TABLE_NAME} {{ comment "owned"; }}'

        with patch.object(
            self.backend,
            "_run",
            side_effect=[table_list, table_body],
        ) as run:
            self.assertEqual(self.backend._table(), table_body)

        self.assertEqual(run.call_count, 2)
        run.assert_any_call("list", "tables")
        run.assert_any_call("list", "table", TABLE_FAMILY, TABLE_NAME)

    def test_similarly_named_table_is_not_accepted(self):
        similar_table = f"table {TABLE_FAMILY} {TABLE_NAME}_backup"

        with patch.object(
            self.backend, "_run", return_value=similar_table
        ) as run:
            self.assertIsNone(self.backend._table())

        run.assert_called_once_with("list", "tables")

    def test_inspection_error_is_not_treated_as_missing_table(self):
        with patch.object(
            self.backend,
            "_run",
            side_effect=FirewallError("inspection failed"),
        ):
            with self.assertRaises(FirewallError):
                self.backend._table()


class NftablesRuleTests(unittest.TestCase):
    def setUp(self):
        self.backend = NftablesBackend(executable="/fake/nft")
        self.table = "\n".join([
            "table inet self_defending_iot {",
            '    comment "managed-by-self-defending-iot-v1"',
            "    set isolated_v4 {",
            "        type ipv4_addr",
            "    }",
            "    set isolated_v6 {",
            "        type ipv6_addr",
            "    }",
            "    chain forward {",
            "        type filter hook forward priority filter; policy accept;",
            "    }",
            "}",
        ])

    def run_with_table(self, initial_table):
        state = {"table": initial_table, "commands": []}

        def fake_run(*args, input_text=None):
            state["commands"].append(args)

            if args[:3] == ("list", "table", TABLE_FAMILY):
                return state["table"]

            if args[:2] == ("add", "rule"):
                rule = " ".join(args[5:])
                marker = "    }\n}"
                if marker not in state["table"]:
                    raise AssertionError("Could not locate forwarding chain end")
                state["table"] = state["table"].replace(
                    marker,
                    f"        {rule}\n    }}\n}}",
                    1,
                )
                return ""

            raise AssertionError(f"Unexpected mocked nft command: {args}")

        return state, fake_run

    def test_creates_and_verifies_all_four_directional_rules(self):
        state, fake_run = self.run_with_table(self.table)

        with (
            patch.object(self.backend, "_ensure_table", return_value=self.table),
            patch.object(self.backend, "_run", side_effect=fake_run),
        ):
            self.backend._ensure_rules()

        required = (
            "ip saddr @isolated_v4 drop",
            "ip daddr @isolated_v4 drop",
            "ip6 saddr @isolated_v6 drop",
            "ip6 daddr @isolated_v6 drop",
        )
        for rule in required:
            with self.subTest(rule=rule):
                self.assertIn(rule, state["table"])

        added_rules = [
            command for command in state["commands"]
            if command[:2] == ("add", "rule")
        ]
        self.assertEqual(len(added_rules), 4)

    def test_existing_correct_rules_are_not_duplicated(self):
        table = self.table.replace(
            "        type filter hook forward priority filter; policy accept;",
            "        type filter hook forward priority filter; policy accept;\n"
            "        ip saddr @isolated_v4 drop\n"
            "        ip daddr @isolated_v4 drop\n"
            "        ip6 saddr @isolated_v6 drop\n"
            "        ip6 daddr @isolated_v6 drop",
        )
        state, fake_run = self.run_with_table(table)

        with (
            patch.object(self.backend, "_ensure_table", return_value=table),
            patch.object(self.backend, "_run", side_effect=fake_run),
        ):
            self.backend._ensure_rules()

        added_rules = [
            command for command in state["commands"]
            if command[:2] == ("add", "rule")
        ]
        self.assertEqual(added_rules, [])

    def test_rejects_existing_chain_with_wrong_hook(self):
        table = self.table.replace("hook forward", "hook input")

        with (
            patch.object(self.backend, "_ensure_table", return_value=table),
            patch.object(self.backend, "_run") as run,
        ):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_rules()

        run.assert_not_called()

    def test_rejects_existing_chain_with_wrong_policy(self):
        table = self.table.replace("policy accept", "policy drop")

        with (
            patch.object(self.backend, "_ensure_table", return_value=table),
            patch.object(self.backend, "_run") as run,
        ):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_rules()

        run.assert_not_called()

    def test_rejects_ipv4_set_with_wrong_type(self):
        table = self.table.replace("type ipv4_addr", "type ipv6_addr", 1)

        with (
            patch.object(self.backend, "_ensure_table", return_value=table),
            patch.object(self.backend, "_run", return_value=table),
        ):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_rules()

    def test_rejects_ipv6_set_with_wrong_type(self):
        table = self.table.replace("type ipv6_addr", "type ipv4_addr", 1)

        with (
            patch.object(self.backend, "_ensure_table", return_value=table),
            patch.object(self.backend, "_run", return_value=table),
        ):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_rules()

    def test_accepts_populated_ipv4_set_with_nested_element_braces(self):
        populated_table = self.table.replace(
            "        type ipv4_addr\n",
            "        type ipv4_addr\n"
            "        elements = { 10.10.10.10 }\n",
            1,
        )
        self.assertIn("elements = { 10.10.10.10 }", populated_table)

        state, fake_run = self.run_with_table(populated_table)

        with (
            patch.object(
                self.backend, "_ensure_table", return_value=populated_table
            ),
            patch.object(self.backend, "_run", side_effect=fake_run),
        ):
            self.backend._ensure_rules()

        self.assertIn("elements = { 10.10.10.10 }", state["table"])

        added_sets = [
            command for command in state["commands"]
            if command[:2] == ("add", "set")
        ]
        self.assertEqual(added_sets, [])

    def test_existing_unowned_table_is_rejected(self):
        unowned = (
            f'table {TABLE_FAMILY} {TABLE_NAME} '
            '{ comment "another-application"; }'
        )

        with patch.object(self.backend, "_table", return_value=unowned):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_table()




    def test_accepts_exact_ownership_marker(self):
        owned = (
            f'table {TABLE_FAMILY} {TABLE_NAME} {{\n'
            '    comment "managed-by-self-defending-iot-v1"\n'
            '}'
        )

        with patch.object(self.backend, "_table", return_value=owned):
            self.assertEqual(self.backend._ensure_table(), owned)

    def test_rejects_ownership_marker_inside_longer_comment(self):
        misleading = (
            f'table {TABLE_FAMILY} {TABLE_NAME} {{\n'
            '    comment "prefix-managed-by-self-defending-iot-v1-suffix"\n'
            '}'
        )

        with patch.object(self.backend, "_table", return_value=misleading):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_table()

    def test_rejects_ownership_marker_with_trailing_text(self):
        misleading = (
            f'table {TABLE_FAMILY} {TABLE_NAME} {{\n'
            '    comment "managed-by-self-defending-iot-v1 other"\n'
            '}'
        )

        with patch.object(self.backend, "_table", return_value=misleading):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_table()

    def test_ownership_marker_cannot_span_lines(self):
        misleading = (
            f'table {TABLE_FAMILY} {TABLE_NAME} {{\n'
            '    comment\n"managed-by-self-defending-iot-v1"\n'
            '}'
        )
        with patch.object(self.backend, "_table", return_value=misleading):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_table()

    def test_rejects_existing_chain_with_wrong_priority(self):
        table = self.table.replace("priority filter", "priority mangle")
        with (
            patch.object(self.backend, "_ensure_table", return_value=table),
            patch.object(self.backend, "_run") as run,
        ):
            with self.assertRaises(FirewallOwnershipError):
                self.backend._ensure_rules()
        run.assert_not_called()

    def test_similar_incomplete_rule_is_not_accepted_as_exact(self):
        body = "\n        ip saddr @isolated_v4 drop counter\n"
        self.assertFalse(self.backend._has_exact_rule(
            body, ("ip", "saddr", "@isolated_v4", "drop")
        ))
        self.assertTrue(self.backend._has_exact_rule(
            "\n ip saddr @isolated_v4 drop # handle 12\n",
            ("ip", "saddr", "@isolated_v4", "drop"),
        ))

    def test_release_refuses_to_modify_unverified_table(self):
        with (
            patch.object(
                self.backend, "_ensure_rules",
                side_effect=FirewallOwnershipError("not owned"),
            ),
            patch.object(self.backend, "_run") as run,
        ):
            with self.assertRaises(FirewallOwnershipError):
                self.backend.release("192.0.2.10")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
