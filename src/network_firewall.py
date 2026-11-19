"""Narrow, ownership-checked nftables backend for IoT gateway isolation.

This module never flushes a firewall ruleset. It only manages its own
dedicated table and only blocks forwarded traffic through this Linux host.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


TABLE_FAMILY = "inet"
TABLE_NAME = "self_defending_iot"
OWNERSHIP_MARKER = "managed-by-self-defending-iot-v1"
CHAIN_NAME = "forward"
SET_V4 = "isolated_v4"
SET_V6 = "isolated_v6"
COMMAND_TIMEOUT_SECONDS = 5


class FirewallError(RuntimeError):
    """A firewall operation could not be safely completed."""


class FirewallUnavailable(FirewallError):
    """The required firewall executable is unavailable."""


class FirewallOwnershipError(FirewallError):
    """The dedicated table exists but is not owned by this application."""


@dataclass(frozen=True)
class FirewallResult:
    success: bool
    action: str
    ip_address: str
    backend: str = "nftables"
    changed: bool = False


class FirewallBackend(Protocol):
    def isolate(self, ip_address: str) -> FirewallResult: ...
    def release(self, ip_address: str) -> FirewallResult: ...


def normalize_ip(value: str) -> str:
    """Accept only a single usable unicast host address."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A device IP address is required")

    candidate = value.strip()
    if "/" in candidate:
        raise ValueError("CIDR ranges are not accepted; provide one device IP")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError("Device IP address is invalid") from exc

    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    ):
        raise ValueError("This IP address is not eligible for isolation")

    return str(address)


class NftablesBackend:
    """Manage a dedicated nftables forwarding table without global flushes."""

    def __init__(self, executable: str | None = None):
        self.executable = executable or shutil.which("nft")
        if not self.executable:
            raise FirewallUnavailable(
                "nftables command 'nft' is not installed"
            )

    def _run(self, *args: str, input_text: str | None = None) -> str:
        try:
            result = subprocess.run(
                [self.executable, *args],
                input=input_text,
                text=True,
                capture_output=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise FirewallError("nftables command timed out") from exc
        except OSError as exc:
            raise FirewallError("Unable to execute nftables") from exc

        if result.returncode != 0:
            # Do not return raw stderr to API clients; it may expose host data.
            raise FirewallError("nftables operation failed")

        return result.stdout

    def _table(self) -> str | None:
        """Return only the exact managed table name, if it exists."""
        output = self._run("list", "tables")
        expected = f"table {TABLE_FAMILY} {TABLE_NAME}"

        if not any(
            line.strip() == expected
            for line in output.splitlines()
        ):
            return None

        return self._run(
            "list", "table", TABLE_FAMILY, TABLE_NAME
        )

    def _ensure_table(self) -> str:
        """Create the dedicated table if absent and verify exact ownership."""
        table = self._table()

        if table is None:
            script = (
                f'add table {TABLE_FAMILY} {TABLE_NAME} '
                f'{{ comment "{OWNERSHIP_MARKER}"; }}\n'
            )
            self._run("-f", "-", input_text=script)
            table = self._table()

        marker_pattern = re.compile(
            rf'(?m)^[ \t]*comment[ \t]+"{re.escape(OWNERSHIP_MARKER)}"[ \t]*;?[ \t]*$'
        )

        if table is None or marker_pattern.search(table) is None:
            raise FirewallOwnershipError(
                "The dedicated nftables table is not owned by this application"
            )

        return table

    def _ensure_rules(self) -> None:
        table = self._ensure_table()

        # Create the chain only when absent. If it already exists, verify
        # that it really is our expected forwarding filter chain.
        chain_pattern = (
            rf"\bchain\s+{re.escape(CHAIN_NAME)}\s*"
            rf"\{{([^{{}}]*)\}}"
        )
        chain_match = re.search(chain_pattern, table, re.DOTALL)

        if chain_match is None:
            self._run(
                "add", "chain", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME,
                "{", "type", "filter", "hook", "forward",
                "priority", "filter", ";", "policy", "accept", ";", "}",
            )
            table = self._run(
                "list", "table", TABLE_FAMILY, TABLE_NAME
            )
            chain_match = re.search(chain_pattern, table, re.DOTALL)

        if chain_match is None:
            raise FirewallError("Unable to verify the forwarding chain")

        chain_body = chain_match.group(1)
        config_lines = []
        for line in chain_body.splitlines():
            if re.match(r"\s*(?:ip|ip6)\s+(?:saddr|daddr)\b", line):
                break
            config_lines.append(line)
        chain_config = " ".join(" ".join(config_lines).split())

        if re.fullmatch(
            r"type filter hook forward priority (?:filter|0); policy accept;?",
            chain_config,
        ) is None:
            raise FirewallOwnershipError(
                "Existing forwarding chain has an unexpected configuration"
            )

        # Verify both address sets by their declared types.
        expected_sets = (
            (SET_V4, "ipv4_addr"),
            (SET_V6, "ipv6_addr"),
        )

        for set_name, address_type in expected_sets:
            table = self._run(
                "list", "table", TABLE_FAMILY, TABLE_NAME
            )
            set_pattern = (
                rf"\bset\s+{re.escape(set_name)}\s*"
                rf"\{{([^{{}}]*)\}}"
            )
            set_match = re.search(set_pattern, table, re.DOTALL)

            if set_match is None:
                self._run(
                    "add", "set", TABLE_FAMILY, TABLE_NAME, set_name,
                    "{", "type", address_type, ";", "}",
                )
                table = self._run(
                    "list", "table", TABLE_FAMILY, TABLE_NAME
                )
                set_match = re.search(set_pattern, table, re.DOTALL)

            if (
                set_match is None
                or re.search(
                    rf"(?m)^\s*type\s+{re.escape(address_type)}\s*;?\s*$",
                    set_match.group(1),
                ) is None
            ):
                raise FirewallOwnershipError(
                    f"Existing set {set_name} has an unexpected configuration"
                )

        # Block both directions. Source rules stop packets originating
        # from an isolated device; destination rules stop packets going
        # to that device through this gateway.
        expected_rules = (
            ("ip", "saddr", f"@{SET_V4}", "drop"),
            ("ip", "daddr", f"@{SET_V4}", "drop"),
            ("ip6", "saddr", f"@{SET_V6}", "drop"),
            ("ip6", "daddr", f"@{SET_V6}", "drop"),
        )

        for family, direction, address_set, verdict in expected_rules:
            table = self._run(
                "list", "table", TABLE_FAMILY, TABLE_NAME
            )
            chain_match = re.search(chain_pattern, table, re.DOTALL)

            if chain_match is None:
                raise FirewallError("Forwarding chain disappeared")

            rule = (family, direction, address_set, verdict)

            if not self._has_exact_rule(chain_match.group(1), rule):
                self._run(
                    "add", "rule", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME,
                    family, direction, address_set, verdict,
                )

        # Verify every required rule after creation.
        table = self._run(
            "list", "table", TABLE_FAMILY, TABLE_NAME
        )
        chain_match = re.search(chain_pattern, table, re.DOTALL)

        if chain_match is None:
            raise FirewallError("Unable to verify the forwarding chain")

        for family, direction, address_set, verdict in expected_rules:
            if not self._has_exact_rule(
                chain_match.group(1), (family, direction, address_set, verdict)
            ):
                raise FirewallError(
                    "Firewall did not confirm all isolation rules"
                )

    @staticmethod
    def _has_exact_rule(
        chain_body: str, expected: tuple[str, str, str, str]
    ) -> bool:
        normalized = " ".join(expected)
        for line in chain_body.splitlines():
            # nft list output appends '# handle N' to rule lines. Ignore only
            # that generated suffix and require the complete expression.
            candidate = re.sub(r"\s+#\s*handle\s+\d+\s*$", "", line.strip())
            candidate = re.sub(r"\s+", " ", candidate).rstrip(";")
            if candidate == normalized:
                return True
        return False

    def _set_for(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        return SET_V4 if address.version == 4 else SET_V6

    def _contains(
        self,
        set_name: str,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        output = self._run(
            "list", "set", TABLE_FAMILY, TABLE_NAME, set_name
        )
        # Match the exact address token, not a substring of another address.
        tokens = re.findall(
            r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f:.]+)(?![0-9A-Fa-f:.])",
            output,
        )
        return str(address) in tokens

    def isolate(self, ip_address: str) -> FirewallResult:
        normalized = normalize_ip(ip_address)
        address = ipaddress.ip_address(normalized)
        set_name = self._set_for(address)

        self._ensure_rules()

        if self._contains(set_name, address):
            return FirewallResult(True, "isolate", normalized, changed=False)

        self._run(
            "add", "element", TABLE_FAMILY, TABLE_NAME, set_name,
            "{", normalized, "}",
        )

        if not self._contains(set_name, address):
            raise FirewallError("Firewall did not confirm the isolation rule")

        return FirewallResult(True, "isolate", normalized, changed=True)

    def release(self, ip_address: str) -> FirewallResult:
        normalized = normalize_ip(ip_address)
        address = ipaddress.ip_address(normalized)
        set_name = self._set_for(address)

        # Validate ownership, chain priority, set types, and every directional
        # rule before modifying the set.
        self._ensure_rules()

        if not self._contains(set_name, address):
            return FirewallResult(True, "release", normalized, changed=False)

        self._run(
            "delete", "element", TABLE_FAMILY, TABLE_NAME, set_name,
            "{", normalized, "}",
        )

        if self._contains(set_name, address):
            raise FirewallError("Firewall did not confirm the release")

        return FirewallResult(True, "release", normalized, changed=True)
