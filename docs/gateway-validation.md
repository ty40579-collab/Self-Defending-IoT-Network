# Controlled nftables gateway validation

This runbook is for an isolated Linux VM or a disposable test gateway with a
private test network. Do not run it against a user's active network. The
application's mock firewall tests do not block packets and do not replace this
procedure.

## Safety conditions

- Use a gateway and two test endpoints that can be rebuilt or discarded.
- Keep an out-of-band console or snapshot recovery path for the gateway.
- Use only test device addresses from a private subnet reserved for this test.
- Confirm that no production route or device uses the test subnet.
- Do not flush the ruleset, remove unrelated tables, or experiment with the
  user's host firewall.
- Run the application with the least privilege that can manage its dedicated
  nftables table. Do not grant broader privileges than needed.
- Keep automatic isolation disabled during initial manual validation.

## 1. Record the test environment

On the disposable gateway, record the kernel, nftables version, identity, and
available network-administration capability:

```bash
uname -a
nft --version
id
grep '^CapEff:' /proc/self/status
```

Confirm the application process has the required network-administration
privilege. A harmless read is useful but does not prove write access:

```bash
nft list tables
```

Run one authorized isolation and release operation against a test address to
confirm write access. Do not test privilege by changing global firewall state.

## 2. Record the pre-test firewall state

Save a read-only snapshot outside the repository and inspect the application
table if it already exists:

```bash
nft -a list ruleset > /tmp/nft-ruleset-before.txt
nft list table inet self_defending_iot
```

If the dedicated table exists, verify that it carries the exact ownership
comment `managed-by-self-defending-iot-v1`. If it does not, the application may
create it. If it exists without that exact marker, stop; the application must
refuse to modify it.

## 3. Verify the configured table

After an authorized isolation operation for the test device, inspect only the
dedicated resources:

```bash
nft -a list table inet self_defending_iot
nft list chain inet self_defending_iot forward
nft list set inet self_defending_iot isolated_v4
nft list set inet self_defending_iot isolated_v6
```

Confirm all of the following from the actual output:

- The table family and name are `inet self_defending_iot`.
- The table ownership comment is exact.
- The `forward` chain is a filter chain with hook `forward`, priority `filter`
  (numeric priority zero), and policy `accept`.
- `isolated_v4` is an `ipv4_addr` set; `isolated_v6` is an `ipv6_addr` set.
- The chain contains exactly the required expressions (nftables may append
  handle comments):

  ```text
  ip saddr @isolated_v4 drop
  ip daddr @isolated_v4 drop
  ip6 saddr @isolated_v6 drop
  ip6 daddr @isolated_v6 drop
  ```

- The test device's normalized address appears in the matching address set.
- No unrelated table or global ruleset was flushed or replaced.

An installed `nft` executable alone does not satisfy these checks.

## 4. Verify packet behavior through the gateway

Connect a test device endpoint and a test service endpoint through the gateway.
First verify that the test service is reachable in both directions before
isolation. Send traffic through the gateway; traffic to or from the gateway
itself does not test the `forward` chain.

Use an authenticated API request to isolate the registered test device. Confirm
the response succeeds, then confirm its address is present in the correct set.
Repeat the same controlled test traffic and verify that test packets to and
from the isolated address are dropped. Use packet captures or endpoint
application logs at both ends to distinguish a firewall drop from a service
failure.

If the test device uses IPv6, repeat the packet test over IPv6 separately. An
IPv4 result does not prove IPv6 behavior.

## 5. Verify release and recovery

Release the test device through the authenticated API. Confirm that:

- The API reports the release only after the firewall confirms it.
- The address is absent from its set unless another active protection record
  still references the same address.
- The application records the device as `recovering` and retains an audit
  action.
- The test traffic succeeds again through the gateway.
- The pre-test ruleset and post-test ruleset differ only in the application's
  owned table and the expected test-address element.

If another active protection record uses the same address, verify that
releasing one record keeps the address blocked. Release the final referencing
record before expecting traffic to resume.

## 6. Verify failure recovery in a disposable copy

Use a separate disposable VM snapshot for negative cases. Create an unowned
same-named table or alter a required chain property only in that disposable
copy, then verify that the application reports a firewall failure and does not
claim successful isolation or release. Confirm that unrelated firewall
resources remain unchanged. Restore the disposable VM snapshot after the test;
do not use a global flush command.

Also test database persistence failure and a rejected/failed compensation using
the application's test doubles. The system must report uncertainty if a
compensating firewall operation is unsuccessful or raises an error.

## Acceptance record

Record the gateway OS and kernel, nftables version, privilege model, table and
rule output, tested IPv4/IPv6 addresses, packet-capture evidence, unrelated
ruleset comparison, release result, and failure-recovery result. Label the
result precisely:

- **Unit-test verified:** mocked application behavior passed.
- **Integration-test verified:** broker and application integration passed.
- **nftables configuration verified:** the real owned table, chain, sets, and
  rules were inspected.
- **Real packet-blocking verified:** packets were observed to stop traversing
  the controlled gateway and resume after release.
- **Production deployment verified:** separate production acceptance evidence
  exists for the actual routing, permissions, recovery plan, and monitored
  deployment.

Passing one level does not establish the next. No real gateway or packet-blocking
verification is claimed by this repository's automated test suite.
