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
