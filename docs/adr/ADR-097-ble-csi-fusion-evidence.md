# ADR 097: BLE and CSI fusion evidence contract

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026 08 23 |
| Relates to | ADR 095, RuView ESP32 telemetry version 1 |

## 1. Context

rvCSI already emits `CsiEvent` as the semantic boundary between radio processing and RuView. BLE must extend that boundary rather than introduce a second event bus or represent unrelated measurements as CSI.

Three radio observations are commonly conflated:

1. WiFi CSI exposes amplitude and phase across OFDM subcarriers.

2. A BLE advertisement exposes a packet RSSI and an application payload. It does not expose coherent carrier phase through the ESP32 S3 public API.

3. Bluetooth Channel Sounding is a cooperative Bluetooth 6 procedure that exposes phase based ranging and round trip timing measurements on supported radios. It is not a BLE advertisement and it is not implemented by ESP32 S3 silicon.

The fusion boundary also needs explicit expiry, confidence, provenance, spoof handling, and abstention. A stale or duplicated token must never silently become a person identity.

## 2. Decision

Extend `CsiEvent` with optional typed sensing evidence, a fusion disposition, quality reasons, a time bounded track association, an event expiry, and a simulation only label. Existing event fields and serialized captures remain readable because every new field has a default and is omitted when empty.

The event remains the shared contract:

```text
CsiEvent
  evidence window ids
  confidence
  disposition
  quality reasons
  sensing evidence
    WiFi CSI track
    BLE advertisement RSSI
    Bluetooth Channel Sounding
  optional track association
  expiry
```

`BleAdvertisementRssi` and `BluetoothChannelSounding` are different tagged payload variants with different `SourceCapability` values. Validation rejects a payload whose claimed capability does not match its variant.

## 3. ESP32 S3 capability boundary

An ESP32 S3 source may claim only these capabilities in this design:

1. `wifi_csi_phase_amplitude`

2. `ble_advertisement_rssi`

It must not claim:

1. `ble_direction_finding_cte_iq`

2. `bluetooth_channel_sounding_phase_timing`

ESP32 S3 does not expose raw Constant Tone Extension IQ through its supported public BLE interface and has no Bluetooth 6 Channel Sounding radio. A second ESP32 C3 does not remove either limitation. The shared 2.4 GHz WiFi and BLE radio also means a requested 20 millisecond advertisement interval is not proof of deterministic 50 Hz sensing while WiFi CSI capture is active.

Channel Sounding can enter the same contract later from a capable Nordic, Silicon Labs, or Espressif radio. Its evidence must identify that radio as the source and must never be attributed to the ESP32 S3 node.

Channel Sounding is represented as one grouped controller procedure, not as an isolated phase sample. RuView telemetry version 1 emits one 72 byte companion record per frequency step. Every record declares a nonzero `source_session_id` as a 32 bit value, a nonzero u32 `procedure_id`, and a 16 bit `procedure_step_count`. The rvCSI aggregator groups those records by source session and procedure, widens the session to an exact decimal u64 JSON string, preserves `procedure_id` as its canonical decimal u32 string, and preserves the declared count alongside the resulting step vector. RVCS carries no authenticated pseudonym or identity join, so `BluetoothChannelSounding` has no `pseudonymous_token` field and cannot establish a `TrackAssociation`.

Each `BluetoothChannelSounding` evidence item also carries the local initiator or reflector role, antenna path, calibration receipt, a verified outer gateway receipt, and a bounded sweep of four to 79 unique channel steps. Publication requires the grouped vector length to equal `procedure_step_count` exactly. RVCS v1 channel indices are zero through 78. The adapter converts signed phase milliradians into canonical `[-π, π)` radians and signed RTT picoseconds into nanoseconds by dividing by 1000; the normalized RTT remains bounded to zero through 250 ns. Validation rejects a zero source session, noncanonical or zero procedure id, a declared count mismatch, repeated or out-of-range channels, noncanonical signed phase, RTT above 250 ns, non-finite values, and sweeps with fewer than four steps. The contract preserves measurements and procedure provenance; it does not claim that one step, or the Bluetooth specification itself, supplies a distance estimate.

## 4. RuView firmware telemetry version 1 mapping

RuView firmware defines a version 1 binary BLE telemetry record carrying an eight byte ephemeral identifier, RSSI, TTL, confidence, node, sequence, and token epoch. Neither that inner record nor RVCS is accepted bare. The host must first verify the outer `RuView/GW/v1` envelope HMAC, exact enrolled node and key, nonzero boot nonce, nonzero replay sequence, authenticated boot-relative receive time, and bounded timing uncertainty. A UDP source address, CRC, inner authenticated flag, or caller-supplied boolean is insufficient. The resulting `VerifiedGatewayEnvelope` receipt is retained with authenticated BLE and Channel Sounding evidence.

| Firmware field | rvCSI field | Rule |
|---|---|---|
| Eight byte ephemeral identifier | `pseudonymous_token` | Derive a new host scoped token. Never serialize or log the raw eight bytes. |
| RSSI | `rssi_dbm` | Preserve the signed value and reject values outside the validated radio range. |
| TTL | `token_expires_at_ns` | Add the checked TTL to the receive timestamp. Preserve this expiry even if the measurement freshness policy is shorter. |
| TTL | `SensingEvidence.expires_at_ns` | Use the earlier of token expiry and the configured measurement freshness deadline. |
| Confidence | `SensingEvidence.confidence` | Normalize to the closed interval from zero to one. Invalid encodings are rejected rather than clamped. |
| Node | `SensingEvidence.source_id` | Map through the configured node registry. Do not place a hardware address in `source_id`. |
| Sequence | `source_sequence` and token replay state | Preserve the authenticated value. A zero, duplicate, or regressing value produces `spoof_suspected` and mandatory abstention. |
| Token epoch | `token_epoch`, pseudonym derivation, and replay window | Preserve the authenticated value and bind both the derived token and sequence state to it. |
| Authentication result | `authentication` and `gateway_envelope` | `authenticated` requires a retained verified `RuView/GW/v1` receipt. Unverified and invalid records cannot carry that receipt. |

To produce the same pseudonym as RuField, derive `HMAC-SHA-256(deployment_key, "rufield.ble.identity.v1\0" || ephemeral_id_8 || little_endian_u64(token_epoch))`. The wire value is exactly `blep:` followed by the full 32 byte digest encoded as 64 lowercase hexadecimal characters. Truncated digests, uppercase hexadecimal, free form labels, hardware addresses, and the old `pt_` form are rejected. The deployment-scoped host key permits authorized receivers in the same deployment to correlate the same ephemeral transmission while preventing raw identifier exposure. Key rotation and the source mapping live outside capture files.

Authentication is processed before association:

1. Only a record inside a cryptographically verified, enrolled `RuView/GW/v1` envelope maps to `authenticated`.

2. A permitted legacy or CRC only record maps to `unauthenticated`, receives degraded or abstained quality with the `unauthenticated_source` reason, and cannot establish a track association.

3. Failed authentication maps to `invalid`, `spoof_suspected`, and `abstained`. Validation rejects an invalid authentication result that is published as usable evidence.

The record maps only to `BleAdvertisementRssi`. Its ephemeral identifier and authentication do not imply Channel Sounding phase or timing. Conversely, an authenticated RVCS procedure carries measurement provenance but no identity join.

## 5. Association and identity semantics

BLE evidence anchors a rotating token to a short lived RF track. It does not name a human.

`TrackAssociation` contains only:

1. A `PseudonymousToken`

2. An opaque CSI track token

3. Confidence

4. Expiry

The application may bind that token to a consented account in a separate governed identity service. rvCSI capture files, ordinary logs, and RuVector embeddings must not contain the binding, BLE MAC addresses, Apple service identifiers, names, emails, or HealthKit identifiers.

Background advertisements from a phone are randomized and are not a stable identity contract. A RuView phone application must provision and rotate its own authenticated token if persistent association is required.

An association is publishable only when the same event contains both of these supports:

1. Non-abstained, authenticated BLE advertisement evidence with `valid` status and the same pseudonymous token. Both its measurement expiry and application-token expiry must cover the complete association lifetime.

2. Non-abstained WiFi CSI evidence with the same opaque track token. Its measurement expiry must cover the complete association lifetime.

Association confidence must be at least 0.60 and cannot exceed the weaker of the eligible BLE and WiFi CSI support confidences. A token by itself, RSSI by itself, a Channel Sounding procedure, or a track by itself cannot create an association. Exact spatial equality at a crossing forces association abstention; a later unambiguous geometry sample must establish a new binding rather than inheriting the pre-crossing track.

## 6. Quality and abstention rules

Every measurement has `usable`, `degraded`, or `abstained` quality. Every event has `observed`, `degraded`, or `abstained` disposition. Expiry is fail closed: evidence, events, application tokens, and track associations are invalid when the evaluation timestamp is equal to the expiry, not only after it.

Typed fusion lifetimes are bounded to five seconds. Deadlines are nested: a valid BLE measurement cannot outlive its token; an event cannot outlive any evidence item or its association; and an association cannot outlive its matching BLE evidence, BLE token, or WiFi CSI track. An event also rejects evidence whose capture timestamp is later than the event publication timestamp. `CsiEvent::validate_at(now_ns)` checks the structural contract and every nested deadline at a monotonic consumer watermark. Simulation and CLI event-output boundaries invoke it immediately before publication.

Nanosecond timestamps and deadlines introduced by this fusion contract serialize to JSON as decimal strings. This preserves all 64 bits through JavaScript and TypeScript. Readers accept legacy numeric event timestamps and deadlines, but writers emit the exact string form.

Evidence carries an explicit privacy class. Exact `respiratory_component` samples and Channel Sounding phase/RTT primitives make their containing evidence P0. `SensingEvidence::validate_for_export` and `CsiEvent::validate_for_export_at` reject P0 at an external output boundary. Exact values may be serialized only after the caller selects the `EdgeOnly` scope; CLI JSON requires the explicit `--include-p0-edge-only` assertion. Human simulation output contains counters only. This scope is a release gate, not permission to transmit P0 across a LAN.

Mandatory abstention applies when:

1. Gross motion contaminates the respiratory component.

2. Token TTL elapsed.

3. Authentication failed.

4. A token is observed simultaneously in physically inconsistent locations.

5. Signal quality is insufficient for the requested interpretation.

An identity association may remain valid during respiratory abstention. This distinction lets RuView preserve track continuity without publishing fabricated vital signs.

## 7. Deterministic simulation

`run_ble_csi_crossing_simulation` produces two synthetic trajectories that cross at one exact midpoint. It first generates raw advertisement records with verified gateway receipts and anonymous CSI candidates. A deterministic stateful replay guard consumes source, gateway receipt, epoch, sequence, and rotating token, while a separate RSSI geometry associator consumes both anchors and the anonymous CSI tracks. These components derive replay, expiry, spoof, association, crossing abstention, and post-crossing rebinding decisions; the generator does not inject those outcomes. An independent ground-truth mapping is consulted only after each decision is complete. The generated stream includes:

1. Anonymous CSI slot ambiguity near the crossing

2. Two BLE RSSI anchors maintaining rotating token association

3. A normalized respiratory waveform

4. Three steps of gross motion contamination with mandatory abstention

5. One expired token rejection

6. One spoof like duplicate token rejection

7. Optional identity-free grouped Channel Sounding procedures with a nonzero source session, canonical decimal u32 procedure id, exact declared four-step count, verified gateway receipt, and four bounded calibrated steps from a separate simulated future radio

The CLI command is:

```sh
cargo run -p rvcsi-cli -- simulate-fusion
cargo run -p rvcsi-cli -- simulate-fusion --json --include-p0-edge-only
cargo run -p rvcsi-cli -- simulate-fusion --channel-sounding --json --include-p0-edge-only
```

Human output contains counters only. Full JSON is an explicitly edge-only, schema-version-3 synthetic fixture. An ungated JSON request fails closed because the fixture contains P0 respiratory components. Repeated runs with the same configuration emit equal reports.

## 8. Security and governance

1. Verify the enrolled `RuView/GW/v1` envelope before parsing an inner radio record, pseudonym derivation, or fusion. Retain its node, key, boot nonce, sequence, receive time, and uncertainty receipt.

2. Keep replay state by authorized source, pseudonymous token, epoch, and sequence. Once a token and epoch is observed expired, a later record cannot resurrect it by advertising a new deadline.

3. Rotate host pseudonym keys and expire associations aggressively. No typed evidence, valid application token, association, or typed event may have more than five seconds of remaining lifetime at creation. The default simulation retains each measurement for 500 milliseconds.

4. Classify exact respiratory samples and exact Channel Sounding phase/RTT as P0. Keep them at the governed edge and do not place them in ordinary logs, external JSON, telemetry, or account bindings.

5. Store raw RF evidence locally with explicit retention. Export semantic events only when possible.

6. Treat respiratory output as an experimental candidate, not diagnosis, sleep staging, ECG, or clinical grade monitoring.

## 9. Consequences

Positive effects:

1. RuView can fuse BLE identity evidence with CSI without weakening the existing validation boundary.

2. Future Channel Sounding radios fit the same event system without pretending current ESP32 hardware supports them.

3. Expiry, replay, spoof, geometry association, quality, and abstention decisions are derived from replayable input and tested against separate ground truth.

Costs and limitations:

1. RSSI normally provides metre scale and environment dependent proximity, not centimetre scale location.

2. Multi person association requires at least two spatially separated BLE receivers or another position source. One RSSI receiver is insufficient at a crossing.

3. WiFi and BLE coexistence scheduling can reduce CSI rate and produce bursty BLE observations.

4. A bearer token can still be transferred with a phone or beacon. Governance must distinguish device association from human identity.

## 10. Acceptance test

The default simulation passes only if it produces 26 valid shared events, publishes no association at the exact crossing, rebinds both subjects on the next unambiguous sample at confidence at least 0.60, records zero association swaps, rejects exactly one expired token and one spoof case, and marks all six motion contaminated candidates as abstained. Hardware acceptance additionally requires repeated two person crossings with zero association swaps across at least 100 trials and explicit abstention whenever token or respiratory evidence is unusable.

## 11. Primary references

1. [Bluetooth SIG Channel Sounding overview](https://www.bluetooth.com/learn-about-bluetooth/feature-enhancements/channel-sounding/) defines phase based ranging and round trip timing and makes clear that the feature does not define a distance algorithm.
2. [Bluetooth Core 6.0 feature overview](https://www.bluetooth.com/core-specification-6-feature-overview/) distinguishes Channel Sounding from RSSI path loss ranging.
3. [Bluetooth LE primer](https://www.bluetooth.com/bluetooth-le-primer/) explains that controller support does not guarantee that a radio feature is exposed through an application API.
4. [Espressif ESP32 S3 BLE feature support status](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/ble/ble-feature-support-status.html) is the platform capability source used by this ADR.
5. [Espressif ESP32 S3 device discovery guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/ble/get-started/ble-device-discovery.html) documents the supported advertisement and scanning path.
