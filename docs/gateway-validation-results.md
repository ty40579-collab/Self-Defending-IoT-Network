# Real Gateway Validation Results

## 1. Scope and result

Date: 2026-11-21 to 2026-11-22

Environment: isolated VMware lab with one Debian gateway and two endpoints
on separate virtual LAN segments.

**Result:** Real IPv4 packet blocking and restoration were verified in both
directions for Endpoint-A and Endpoint-B through the controlled gateway.

This is isolated-lab validation, not production deployment acceptance.

## 2. Gateway environment

- OS: Debian GNU/Linux 13.7.0 (amd64)
- Kernel: 6.12.107+deb13-amd64
- nftables: v1.1.3
- Python: 3.13.5
- Gateway hostname: gateway
- Application service: self-defending-iot.service
- Application account: sdiot
- API bind address: 127.0.0.1:5000
- Firewall privilege: CAP_NET_ADMIN through systemd ambient and bounding capabilities
- Automatic isolation: disabled
- nftables.service: disabled

## 3. Lab topology

| System | Interface | IPv4 address | Network |
|---|---|---|---|
| Gateway | ens37 | 10.10.10.1/24 | SDIoT-LAN-A |
| Gateway | ens38 | 10.10.20.1/24 | SDIoT-LAN-B |
| Endpoint-A | ens33 | 10.10.10.10/24 | SDIoT-LAN-A |
| Endpoint-B | ens33 | 10.10.20.10/24 | SDIoT-LAN-B |

The endpoints were attached to separate Layer-2 LAN segments. Their
inter-subnet traffic traversed the gateway forwarding path. IPv4 forwarding
was enabled and persisted through reboot.

## 4. nftables configuration

The application-managed table was `inet self_defending_iot`.

- Ownership comment: `managed-by-self-defending-iot-v1`
- Chain: `forward` (filter hook, priority filter, policy accept)
- Sets: `isolated_v4` (`ipv4_addr`) and `isolated_v6` (`ipv6_addr`)

The chain contains source and destination drop rules for both IPv4 and IPv6 isolation sets.
The target address was inserted during isolation and removed after release.
The initial gateway ruleset was empty. No global ruleset flush was used.

## 5. Real IPv4 packet-blocking tests

### Endpoint-A

- Address: `10.10.10.10`; peer: `10.10.20.10`.
- Baseline connectivity succeeded.
- Isolation API returned HTTP 200; the address was added to `isolated_v4`.
- Traffic in both directions was blocked during isolation.
- Release API returned HTTP 200; the address was removed.
- Connectivity was restored after release.

### Endpoint-B

- Address: `10.10.20.10`; peer: `10.10.10.10`.
- Isolation and release API requests returned HTTP 200.
- Timestamped ping logs showed 16 consecutive missing replies in each direction during isolation.
- Replies resumed after release; final active isolation count was zero.

Endpoint-B isolation interval (UTC): 2026-11-22 05:06:23.502950 to 05:06:31.956394.

These tests verified real IPv4 packet blocking through the isolated gateway, not only mocked firewall commands.

## 6. API security and service recovery

- An invalid bearer token was rejected with HTTP 401.
- The nftables table was unchanged after the rejected request.
- The API service was restarted successfully.
- The health endpoint returned HTTP 200 after restart.
- The application-managed nftables table was preserved across the service restart.
- Active isolation count remained zero.
- Automatic isolation remained disabled.

The checks confirm that an unauthenticated isolation request did not modify the firewall and that an API process restart did not remove the application-managed firewall configuration.

## 7. Gateway reboot and persistence

- The gateway rebooted successfully.
- The application service returned to active and enabled state.
- All three gateway interfaces and their configured IPv4 addresses returned.
- The expected routes were restored.
- IPv4 forwarding remained enabled (`net.ipv4.ip_forward=1`).
- The SQLite database passed its integrity check before and after reboot.
- Both endpoint records and their protection history remained in the database.
- The kernel nftables table was empty immediately after reboot, as expected.
- A subsequent authorized isolation request recreated the application-managed table.
- Release removed the endpoint address from the isolation set.
- Final active isolation count was zero, and both endpoints were reachable.

The firewall table is recreated by the application when isolation is next requested; this test does not claim that nftables rules automatically persist across reboot.

## 8. Automated verification

- Full test suite: 89 passed, 12 skipped, and 18 subtests passed.
- Python compile check: `python -m compileall -q app.py src tests` succeeded.
- Git whitespace validation: `git diff --check` succeeded.
- nftables populated-set parser regression test passed.

The parser correction was committed and pushed to branch `phase4/automated-network-protection`.
- Commit: `731b399ce21f745c6bd8a88f96004bbd84ba57ea`

## 9. Limitations and acceptance status

### Verified

- Real bidirectional IPv4 isolation and release for both endpoints.
- API authentication rejection and service-restart recovery.
- Gateway reboot, database integrity, network configuration, and IPv4 forwarding persistence.
- Firewall table recreation and successful release after reboot.
- Automated regression and full test suite.

### Not verified or outside this test scope

- Routed IPv6 isolation: IPv6 addresses, routes, and forwarding were configured, but endpoint-to-endpoint connectivity was intermittent. A stable IPv6 baseline could not be established, so IPv6 packet blocking and release were not tested.
- Production deployment, production traffic, and production security acceptance.
- Every possible failure scenario, including all firewall ownership conflicts and database failure conditions.
- Automatic restoration of kernel nftables rules immediately at boot; the table was recreated on the next isolation request.

## 10. Overall conclusion

The controlled VMware lab demonstrated working manual IPv4 device isolation and release through a dedicated nftables gateway for two endpoints on separate LAN segments. API security, service recovery, reboot persistence of application data and network configuration, and automated tests also passed.

These results support isolated-lab acceptance. They do not establish production readiness or complete IPv6 validation.
