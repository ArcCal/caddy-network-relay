# Native H3 delivery coverage follow-up

## Result

Nine additional native Apple Relay download stalls have complete, contiguous
sent and acknowledged coverage for every observed stream byte. Eight exhaust
connection credit; one exhausts stream credit with connection credit remaining.
The tested transfers still fail. This is stronger transport evidence, not a
repair or proof that the receiving application consumed those bytes.

The diagnostic overlay changes only observation. It records STREAM byte ranges
and associates them with 1-RTT packet numbers, then merges ranges covered by
received ACKs. Highest packet numbers and highest stream offsets alone are not
used as delivery proof. Interval and packet metadata have explicit bounds and
sticky truncation flags; none of the nine accepted observations is truncated.
Late ACKs and retransmissions are supported. Outstanding records can represent
lost original packets whose bytes were acknowledged in retransmitted packets.
No zero-wire-loss claim follows from these results.

The original Apple Relay schema and RFC 9000 sections 4.1, 4.2, 13.3 and 19.8
were reviewed. A sender must not exceed either advertised credit limit. ACKs
confirm transport receipt, not application consumption or available receive
buffer space. The receiver must not require a blocked notification before
issuing further credit. Previous periodic DATA_BLOCKED candidates failed to
restore progress and remain excluded from production.

## Exact runs and validation

Diagnostic revision: `54c47dda032ffc4e8e1fb8c6981becbb3bff2d82`.
Baseline Caddy source: `a691271ac5362cec324231234f38990680630fda`.
Candidate Caddy source: `49549117e643ad4a05bb1a639ca17cf8521a4356`.
The candidate runtime corresponds to main; subsequent main changes concern
tests and documentation. Source manifests, the observation-only overlay,
prepared Go policy, binaries and probe identities all pass independent checks.
Both runs execute race-enabled observer tests for both arms before measurement.

| OS | Run | Baseline cases / samples / rejections | Candidate cases / samples / rejections | Overall result |
| --- | --- | --- | --- | --- |
| macOS 15 | [43521542631](https://github.com/ArcCal/network-relay/actions/runs/43521542631) | 96 / 336 / 48 | 96 / 336 / 48 | Failed |
| macOS 27 | [43521170352](https://github.com/ArcCal/network-relay/actions/runs/43521170352) | 95 / 332 / 48 | 96 / 336 / 48 | Failed |

All exact negative controls pass. The macOS 27 baseline driver skipped the
four-stream case in round 1 after the single-stream failure; this is a missing
case, not a pass. A later diagnostic-only correction continues collection after
an observed download failure without changing acceptance criteria. Free disk
remains at least 45,212,307,456 and 42,526,269,440 bytes in the macOS 15 arms,
and 35,681,259,520 and 34,867,077,120 bytes in the macOS 27 arms.

Each row below represents a failed case, with five stable snapshots over the
stated interval. All sent bytes are contiguously ACKed from offset zero. There
is no FIN or STOP_SENDING on the affected data streams before cancellation.

| OS | Arm | Round / mode / streams | Limiting credit, bytes | Stable seconds |
| --- | --- | --- | ---: | ---: |
| 15 | baseline | 7 / auto / 4 | 30,298,386 (connection) | 80.260 |
| 15 | baseline | 8 / auto / 4 | 195,918,739 (connection) | 80.343 |
| 15 | candidate | 0 / h3 / 4 | 33,591,675 (connection) | 80.237 |
| 15 | candidate | 3 / h3 / 4 | 64,619,252 (connection) | 80.207 |
| 15 | candidate | 7 / auto / 4 | 123,338,950 (connection) | 80.314 |
| 15 | candidate | 8 / auto / 4 | 107,434,828 (connection) | 80.325 |
| 15 | candidate | 9 / h3 / 4 | 232,852,248 (connection) | 80.384 |
| 27 | baseline | 1 / h3 / 1 | 12,629,854 (stream) | 80.491 |
| 27 | candidate | 7 / auto / 4 | 121,885,014 (connection) | 80.371 |

The single-stream macOS 27 case has 4,147,350 bytes of unused connection
credit. Its last recorded STREAM_DATA_BLOCKED limit is lower than the final
stream limit. The observer records the last frame, including retransmissions,
not a monotonic maximum or a complete history of blocked notifications. This
field alone cannot establish that the current notification was never sent.
The goroutine snapshot confirms the upload to the QUIC send stream is waiting.
Further attribution requires additional evidence; no speculative production
change is made from the stale last-frame value.

## Retained artifact identity

| OS | Artifact ID | ZIP SHA-256 |
| --- | --- | --- |
| 15 | 14084573200 | `3cf9ad5c19f9c406f2f90a0534507561849fe9279184545d4ffcc91875adac65` |
| 27 | 14083523285 | `d42e4f6d897b8dbeec4707f338c13636df6a69a0e4ff023d5a793649b8bb2659` |

The downloaded ZIPs, full job logs, extracted traces, source manifests and
independent analyses are retained in the audit workspace. GitHub diagnostic
artifacts have a short retention period. These loopback, explicitly configured
URLSession Relay observations do not establish installed-profile, physical
iPhone, WAN or production throughput acceptance. Native H2 UDP truncation,
Rust serial H2 performance and historical CF/WARP long-run failures remain
separate open investigations.
