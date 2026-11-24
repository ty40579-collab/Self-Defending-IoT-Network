# Self-Defending IoT Network — Final Gateway Acceptance Report

**Date:** 24 November 2026
**Branch:** `phase4/automated-network-protection`
**Gateway:** Debian-based VMware gateway
**Scope:** Gateway firewall integration, startup initialization, API isolation/release, IPv4/IPv6 validation, and reboot validation.

## 1. Verified application and API results

- The `self-defending-iot.service` systemd service runs under the dedicated `sdiot` account.
- The service has `CAP_NET_ADMIN` for its firewall operations.
- The authenticated protection API successfully isolated and released Endpoint B.
- IPv4 isolation membership was verified after isolation and removal was verified after release.
- The IPv4 API integration test reported `TASK 1 PASSED`.
- A separate IPv6 device record was registered through the real API. The API successfully isolated and released its IPv6 address.

## 2. Firewall ownership and rules

- The project-owned nftables table is `inet self_defending_iot`.
- The ownership marker is `managed-by-self-defending-iot-v1`.
- The table contains `isolated_v4` and `isolated_v6` address sets.
- Its forwarding chain contains source and destination drop rules for both IPv4 and IPv6.
- The system-wide `nftables.service` remains intentionally inactive.
- No global ruleset flush was performed.
- Automatic device isolation remains disabled.

## 3. IPv4 validation

- Endpoint A and Endpoint B have working IPv4 connectivity through the gateway.
- API-driven isolation and release of Endpoint B were verified through the running service.
- Firewall set membership was verified after isolation and confirmed empty for the device after release.

## 4. IPv6 validation

- The gateway has `fd10:10:10::1/64` on `ens37` and `fd10:10:20::1/64` on `ens38`.
- IPv6 forwarding is enabled and the connected routes were verified.
- Gateway-to-endpoint IPv6 connectivity succeeded for both endpoints.
- Endpoint A-to-Endpoint B and Endpoint B-to-Endpoint A IPv6 connectivity succeeded.
- Through the authenticated protection API, the IPv6 address `fd10:10:10::10` was isolated and appeared in `isolated_v6`.
- During isolation, Endpoint B's ping to Endpoint A failed with 100% packet loss, confirming that the firewall blocked the tested traffic.
- The API release operation removed the address from `isolated_v6`.
- Endpoint B-to-Endpoint A IPv6 ping subsequently succeeded with 0% packet loss.

**IPv6 live isolation and connectivity-restoration validation: PASS.**

## 5. Recovery eligibility limitation

The release operation correctly left the test device in `recovering` state rather than automatically marking it active. The recovery assessment reported that no trained intelligence baseline existed and that three fresh telemetry observations after release were required but unavailable.

This is an expected safety gate, not a failed firewall release. Recovery eligibility and completion must not be forced without the required baseline, fresh telemetry, and clean assessments. The temporary IPv6 API test record and its protection/event history were retained for auditability.

## 6. Startup and reboot

- Application startup initialization is guarded by the configured enforcement-enabled state.
- The application compiled and the service restarted successfully after this change.
- A gateway reboot was performed.
- After reboot, the application service and Gunicorn worker started successfully.
- The project firewall table was present after reboot.
- Both `isolated_v4` and `isolated_v6` were verified empty after reboot.
- The system-wide `nftables.service` remains intentionally inactive.

## 7. Test and code-quality validation

- A project test run reported `119 passed, 23 subtests passed`.
- Python compilation passed for `app.py`, `src`, and `tests`.
- `git diff --check` passed.
- Final full test suite: PASS (`119 passed, 23 subtests passed in 16.07s`).
- Final staged-diff checks remain to be completed before commit.

## 8. Acceptance summary

| Area | Status |
|---|---|
| Protection API IPv4 isolate/release | PASS |
| Project-owned firewall rules | PASS |
| Application startup initialization | PASS |
| Gateway reboot and firewall recreation | PASS |
| Empty isolation sets after reboot | PASS |
| IPv4 network validation | PASS |
| IPv6 bidirectional connectivity | PASS |
| IPv6 API isolation and traffic blocking | PASS |
| IPv6 release and connectivity restoration | PASS |
| Automatic isolation disabled | PASS |
| Recovery completion for the temporary IPv6 test device | NOT ELIGIBLE — required baseline and fresh telemetry were unavailable |
| Final full test suite after all current changes | PASS (`119 passed`, `23 subtests`) |

**Overall status:** Gateway, firewall, API, IPv4, IPv6, and reboot acceptance checks passed. Automated recovery completion remains correctly gated pending the required intelligence baseline and fresh telemetry.
