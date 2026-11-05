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

A backend that cannot run a scenario prints a row of `n/a` with the reason; nothing is skipped silently:
NFQUEUE has no `sniff` (every queued packet needs a verdict), AF_PACKET has no `hold*`.

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
about 2,033-2,040 us. NFQUEUE `sniff` and AF_PACKET `hold*` remain unsupported as described above.

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

The clearest comparison is at the tested game-scale rate of 20,000 pps: both platforms delivered the traffic without
reported loss, but Linux had lower measured latency for immediate verdicts. The Windows baseline p50 was 9 us versus
3-4 us on Linux. With `hold0`, Windows p50 rose to 26 us, compared with 7-10 us for Linux swdivert and NFQUEUE; batching
was 36 us on Windows and 7-9 us on Linux. These are end-to-end measurements on different hosts and paths, so they show
the outcome of these particular setups, not an isolated operating-system or backend cost.

At 100,000 pps, reliability and tail behavior separate much more sharply in this run. Linux swdivert and NFQUEUE
delivered essentially all sent packets for both payload sizes in the runnable hold scenarios. Windows WinDivert did
not: `hold0` lost about 60-61%, `hold0-batch` about 23-27%, and `hold2ms` about 29-30%. For the packets that arrived,
Windows `hold0` p99 latency was roughly 59-80 ms, while Linux swdivert `hold0` p99 was 40-45 us. Windows `hold2ms`
also accumulated multi-second tail latency and very large verdict-overdue time, whereas Linux `hold2ms` stayed close
to its intended 2 ms delay, with p99 around 2.1-2.2 ms.

In practical terms, Linux was both faster and more reliable under this stress test; on Windows, batching improved
delivery compared with one verdict call per packet but did not make the 100,000-pps load reliable. At 20,000 pps,
WinDivert delivered traffic reliably, though with higher measured immediate-verdict latency than the Linux backends.
Latency percentiles describe received packets only, so they must be read alongside `lost` and `missed`; when many
packets are dropped, low latency among survivors would not mean the path is healthy. These findings are limited to
one 8-CPU machine per OS, the tested loopback/namespace paths, and this one-flow UDP workload. Repeat on equivalent
hardware and the intended NIC/game path before drawing conclusions about Windows versus Linux generally.
