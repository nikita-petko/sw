# Unified measurement strategy for the backend benchmarks

Every backend is measured with the same scenarios, the same traffic, the same measurements and the same report, so that rows
of different backends (and operating systems) can be compared directly. The single definition is
[`pocs/bench_common.py`](../pocs/bench_common.py); the platform drivers only start the scenario for their backend.

| Part | File |
|---|---|
| Definition (scenarios, sweep, columns, summary, report) | `pocs/bench_common.py` |
| Windows driver + tool | `pocs/windivert_benchmark/bench.py`, `wdbench.cc` |
| Linux driver + tool | `pocs/linux_kernel_module_backend/bench.py`, `swbench.cc` |
| One command per machine | `pocs/run_benchmarks.py` |

```
python pocs/run_benchmarks.py                       # Windows (elevated) or Linux (sudo adds swdivert)
python pocs/bench_common.py report a.json b.json    # one table from the --json files of several machines
```

## Scenarios (same names and meaning everywhere)

| Scenario | What happens to each packet |
|---|---|
| `baseline` | no backend attached |
| `sniff` | the backend gets a copy; the original is not held |
| `hold0` | held, verdict at once, one verdict call per packet |
| `hold0-batch` | held, verdict at once, calls batched (16 packets per receive on Windows; everything one receive returned on Linux) |
| `hold2ms` | held, verdict 2 ms after capture (the engine's behaviour) |

A backend that cannot run a scenario prints a row of `n/a` with the reason; nothing is skipped silently. AF_PACKET is the Linux
passive-copy reference for `sniff` (see the [AF_PACKET PoC](../pocs/linux_afpacket_backend.md)) and cannot run `hold*`.
NFQUEUE can emulate sniff by queueing each packet and immediately accepting it, but that adds a userspace verdict round
trip; the current shared benchmark does not count that as a passive-copy scenario and reports NFQUEUE `sniff` as `n/a`.

## Traffic and procedure (same everywhere)

- One UDP flow to port 9000, paced sender, payload 64 and 1200 B, 20,000 pps (game scale) and 100,000 pps (saturating stress row).
- 5 s per run, 3 runs per cell, the cell is the median (latency max: the worst run).
- Sender, backend reader and sink run on one machine, so one clock (`CLOCK_MONOTONIC` / `QueryPerformanceCounter`) stamps
  every packet. The payload carries the send time and a sequence number.
- Path: loopback (Windows) or `veth` through a gateway namespace (Linux). It is recorded in the result details; repeat with
  `--dst <local interface IP>` or a real NIC for the NIC path.
- Same capture length (`--snap 224`) for every Linux reader, and the same WinDivert queue settings as the shipped backend.

## Measurements (same columns everywhere)

| Column | Meaning |
|---|---|
| `sent`, `recv`, `lost`, `dups`, `reord` | what the sink saw: loss, duplicates, reordering the backend introduced |
| `missed` | sent minus captured: packets the backend never saw |
| `lat p50/p99/p99.9/max` | sender stamp to sink: end-to-end cost, read against `baseline` |
| `cap p50/p99` | sender stamp to the reader seeing the packet: kernel or driver side |
| `over p99` | verdict due to verdict call (hold2ms): our scheduling |
| `send p99` | duration of one verdict call: re-injection |
| `reader cpu us/pkt` | the backend reader process's CPU per captured packet |
| `host cpu us/pkt`, `vs baseline` | host-wide CPU minus sender and sink per sent packet, and its difference to the baseline row |

Reading it: `lat(hold) - lat(baseline)` is the total cost; `cap` and `send` locate it in the kernel/driver, `over` in user-space
scheduling; `lost`, `reord` and `dups` show what the diversion broke.

## Reporting

Both drivers print the same markdown table (`bench_common.render`) and write the same JSON (`--json`), which `run_benchmarks.py`
saves next to the log. `bench_common.py report` merges files from several machines into one table.

## Known limits

- Host-wide CPU includes whatever else runs; use an idle machine and read it against `baseline`.
- On Linux the swdivert ring has no receive timestamp: `cap` is taken when the reader drains the ring, so it includes the
  reader's wake-up (the same holds for the WinDivert reader, which is stamped when `WinDivertRecvEx` returns).
- Loopback or `veth` is not the real gameplay path; the in-game symptoms need a timestamped in-game trial.
- Linux-only diagnostics that the common table does not carry (polls, kernel wake-ups, the module's held/resumed counters) are
  still printed by `swbench sniff`.

## Initial results (2026-11-04/05)

The initial report contains runs from two 8-CPU hosts: Windows 10 build 19045 and Arch Linux kernel 7.2.11. The table
below selects the 100,000-pps stress rows; latencies are in microseconds. These are snapshots from those hosts, not a
cross-machine performance guarantee.

| OS | Backend | Scenario | Payload | Received / sent | Lost | Lat p50 / p99 | Over p99 |
|---|---|---|---:|---:|---:|---:|---:|
| Linux | swdivert | hold0 | 64 | 499,997 / 499,997 | 0 | 8 / 45 | 0 |
| Linux | swdivert | hold0-batch | 64 | 499,997 / 499,997 | 0 | 7 / 42 | 0 |
| Linux | swdivert | hold2ms | 64 | 499,999 / 499,999 | 0 | 2,021 / 2,102 | 75 |
| Linux | swdivert | hold0 | 1200 | 499,994 / 499,994 | 0 | 8 / 40 | 0 |
| Linux | swdivert | hold0-batch | 1200 | 499,994 / 499,994 | 0 | 6 / 44 | 0 |
| Linux | swdivert | hold2ms | 1200 | 499,994 / 499,994 | 0 | 2,017 / 2,098 | 75 |
| Windows | windivert | hold0 | 64 | 200,174 / 500,000 | 299,826 | 40,982 / 80,242 | 0 |
| Windows | windivert | hold0-batch | 64 | 383,569 / 500,000 | 116,431 | 40,993 / 42,258 | 5 |
| Windows | windivert | hold2ms | 64 | 356,235 / 500,000 | 143,765 | 2,108,762 / 3,660,750 | 3,807,877 |
| Windows | windivert | hold0 | 1200 | 195,658 / 500,000 | 304,342 | 32,502 / 58,659 | 0 |
| Windows | windivert | hold0-batch | 1200 | 365,306 / 500,000 | 134,694 | 32,521 / 33,480 | 5 |
| Windows | windivert | hold2ms | 1200 | 349,697 / 500,000 | 150,303 | 2,202,847 / 3,502,129 | 3,585,196 |

At 20,000 pps, all runnable rows delivered every packet the sender reported (100,000 or 99,999 per cell), with no
reported loss. WinDivert's `hold0` p50 was 26 us and
`hold0-batch` was 36 us, compared with a 9 us Windows baseline; `hold2ms` p50 was about 2,024 us. On Linux, swdivert
and NFQUEUE also delivered all packets in the runnable cases; their `hold0` p50s were 7-10 us and `hold2ms` p50s were
about 2,033-2,040 us. The shared benchmark does not report NFQUEUE `sniff` (which would include a verdict round trip) or
AF_PACKET `hold*`, as described above.

At 100,000 pps, the Linux swdivert runs still delivered essentially all packets for both payload sizes. In contrast,
WinDivert lost 23-27% of packets in `hold0-batch` and about 60-61% in `hold0`; `hold2ms` lost about 29-30%, with
multi-second end-to-end latency and a large `over p99`. This indicates that the tested Windows setup could not sustain
the offered stress load, especially for per-packet verdicts. Treat the results as a signal to investigate saturation
and queueing, not as a claim about all Windows systems or real gameplay traffic.

The 100,000-pps WinDivert `sniff` rows also sent fewer packets than the nominal target in the report. When interpreting
stress results, distinguish offered rate from actual `sent`, and inspect `missed` as well as `lost`: they describe
different stages of the path. Small or negative `vs baseline` CPU differences are within the context of host-wide CPU
measurement and should not be read as proof that a backend reduces CPU use.

## What the results say about speed and reliability

The comparisons below use p50 end-to-end latency (`lat p50`) and packet delivery (`received / sent`). A lower latency
of `A` versus `B` is expressed as `(B-A)/B` percent lower and `B/A` times lower. A delivery ratio is not a general
reliability score: it describes only packets delivered in these runs. Percentages are rounded, and all results are
from the tested hosts and paths.

### Overall comparison across the shared hold scenarios

This composite covers all 12 matched cells: `hold0`, `hold0-batch` and `hold2ms`, each at 20 kpps and 100 kpps with
64- and 1200-byte payloads. Each cell has equal weight in the latency comparison: we take the geometric mean of the
12 per-cell p50 latency ratios, so the intentionally 2-ms hold does not overwhelm the microsecond scenarios merely
because it has a larger absolute latency. Delivery is pooled as total received divided by total sent across those
cells, so the 100-kpps cells contribute in proportion to their packet counts. Baseline is excluded because it has no
backend; sniff is excluded because NFQUEUE has no sniff mode and the cited WinDivert results do not provide matching
sniff latency data.

| Comparison | Overall p50 latency | Overall delivery | Takeaway |
|---|---|---|---|
| Linux swdivert vs. NFQUEUE | swdivert about **26.8% lower** (about **1.37x lower latency**) | Both **100%**; swdivert 3,599,974/3,599,974, NFQUEUE 3,599,986/3,599,986 | swdivert has the lower composite median, but its composite p99 is only about 4% lower; no delivery/reliability winner was measured |
| Linux swdivert vs. Windows WinDivert | swdivert about **98.9% lower** (about **90x lower latency**) | Linux **100%** vs. Windows about **68.1%**; about **+31.9 percentage points** and **1.47x as many packets delivered** | The large difference is driven by Windows saturation in the 100-kpps stress cells; it is not a general OS/backend guarantee |
| Linux NFQUEUE vs. Windows WinDivert | NFQUEUE about **98.5% lower** (about **66x lower latency**) | Linux **100%** vs. Windows about **68.1%**; about **+31.9 percentage points** and **1.47x as many packets delivered** | Same cross-host caveat; Linux backends had equivalent measured delivery in this test |

For the Linux-only comparison, swdivert's reader CPU per packet was about **44% lower** overall; equivalently,
NFQUEUE used about **1.79x as much reader CPU time per packet** by the same geometric-mean method. This is process
CPU, not host-wide CPU or total system power.

The cross-OS latency ratios are approximate: the Windows 20-kpps values are reported as rounded ranges, and the
Windows and Linux results came from different machines and paths. The cited Windows run was a single run per cell,
whereas the Linux table is the median of three runs. Also, latency percentiles describe received packets only; the
Windows 100-kpps latency is for surviving packets while many others were dropped. The delivered-packet comparison
(100% vs. about 68%) is more informative for reliability in this particular combined workload. Since Linux recorded
zero losses, a finite “X-times more reliable” loss-rate ratio is undefined; report the delivery percentage-point
difference and delivered-packet ratio instead.

These are initial results from one 8-CPU machine per OS, loopback on Windows and a namespace/veth path on Linux, using
one UDP flow and 64- or 1200-byte payloads. Repeat on equivalent hardware and the intended NIC/game path before
drawing conclusions about Windows versus Linux generally.
