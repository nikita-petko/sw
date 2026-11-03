# Research note: packet backend comparison (WinDivert, NFQUEUE, swdivert kernel module, others)

## Status

Windows numbers are measured (loopback, one machine). Linux numbers for NFQUEUE and the `swdivert` kernel module are taken
from the existing bare-metal results in [`pocs/linux_kernel_module_backend.md`](../pocs/linux_kernel_module_backend.md)
(Phase 3 and 4 results); they were **not** produced with the same parameters or the same metrics as the Windows run, so
the two sides are not directly comparable yet. Cells marked TODO are to be filled in on Linux by running the matching
benchmark. Nothing here was measured on the real gameplay path (ethernet to host, routed through ProtonVPN).

## Question

Is the perceived difference between the Windows and Linux hosts a packet-backend (driver) issue or an interface issue
(the path through the host and what the engine does with the packets)?

## Observations that motivated this

- Windows: clients connect to the host through ethernet and are routed through a ProtonVPN interface. Weapon swapping
  almost always succeeds.
- Linux: shotgun damage lands more often than sniper damage. A slight delay on re-sync is sometimes seen. It is rare,
  and it sometimes also occurs on Windows.

These are anecdotal and have not been measured with the same setup on both platforms.

## Backends in scope

| Backend | Location | Platform | Mechanism | Benchmark |
|---|---|---|---|---|
| WinDivert | `backends/windivert` | Windows | WinDivert 2.2.2 driver, network and forward layers, one receive thread per layer, user-space scheduling | `pocs/windivert_benchmark` (`wdbench`, `bench.ps1`) |
| NFQUEUE | `backends/nfqueue` | Linux | nftables rules (in-process netlink) queue packets to `libnetfilter_queue`; verdict per packet | `pocs/linux_kernel_module_backend` (`swbench`, `bench.py`, modes `nfq`, `nfq-hold`) |
| swdivert (kmod) | `backends/kmod`, `kmod/` | Linux, out of tree | kernel module with a shared ring, steal-and-resume verdicts, in-kernel checksums | same (`swdiv`, `swdiv-hold`, `backend` modes) |
| AF_PACKET | none (benchmark reference only) | Linux | TPACKET_V3 capture, no hold | `swbench` mode `afpacket`; sniff-only reference |
| stub | `backends/stub` | any | no packet access | not applicable |
| tc/netem | `pocs/linux_tc_netem_backend.md` | Linux | kernel delays, no user-space hop | proposal only, nothing built or run |
| eBPF/netlink | `pocs/linux_ebpf_netlink_backend.md` | Linux | per-packet logic in kernel; its Change A (in-process netlink rules) and Change C are in the NFQUEUE backend | not benchmarked here |

## Tooling

### One command for either system

`pocs/run_benchmarks.py` detects the OS, builds the benchmark binaries, runs the matching suite with the Linux defaults
(rates 20000,100000, payloads 64,1200, 5 s, 3 runs) and saves one log with the machine details to
`build/benchmarks/<host>-<os>-<time>.log`, so two logs can be compared directly.

```
python pocs/run_benchmarks.py             # Windows: elevated shell
sudo python3 pocs/run_benchmarks.py       # Linux: root adds the swdivert rows when swdivert.ko is loaded
python3 pocs/run_benchmarks.py --quick    # short check of the whole chain
python3 pocs/run_benchmarks.py --egress   # also probe every egress interface (below)
```

### Latency per egress (ethernet, wlan, ProtonVPN), with and without the diverter

`pocs/egress_benchmark/egress.py` (Windows and Linux) sends UDP DNS queries out of each interface and reports round-trip
p50/p95/p99/max, jitter and loss per egress. The egress is forced per socket (`IP_UNICAST_IF` on Windows,
`SO_BINDTODEVICE` on Linux). With `--hold MS` and an elevated shell it repeats each egress with the diverter in the path
(`wdbench hold` on Windows, `swbench backend` on Linux) and reports how many packets the diverter captured.

```
python pocs/egress_benchmark/egress.py list
python pocs/egress_benchmark/egress.py probe --egress wlan="WiFi 2" --egress proton=ProtonVPN --egress eth=Ethernet --hold 0 --hold 2
```

Forwarded traffic (a client behind the host): on the host run `egress.py hold --egress ProtonVPN --seconds 60`
(forward layer; on Windows the filter selects the egress with `ifIdx`, on Linux the filter has no interface field and
matches the client's address instead), and at the same time on the client `egress.py probe --default via-proton --count 400`.
Repeat after switching the host's egress; `egress.py compare FILE...` prints saved results from several machines together.
`hold` reports a capture count: 0 means the client's traffic did not take the forward path.

Smoke test on the Windows host (no diverter): the default route (ProtonVPN) to 1.1.1.1 gave p50 about 10 ms, forcing the
ProtonVPN interface gave p50 9.95 ms and p99 11 ms with no loss. Forcing the WiFi interface lost every query, probably the
ProtonVPN kill switch or the network dropping UDP/53 (not established), and the ethernet interface is an internet-sharing
network with no gateway. The forwarded-path `hold` and the `--hold` variants were not run (they need an elevated shell).

### Windows: `pocs/windivert_benchmark`

| Part | Role |
|---|---|
| `wdbench flood` | Paced UDP sender. Each payload carries a send timestamp (bytes 0-7) and a sequence number (8-15, stream in the high 32 bits). |
| `wdbench sink` | Records one-way latency, loss, duplicates and reordering. |
| `wdbench hold` | WinDivert divert-and-resume reader. Every packet gets a verdict D ms after capture, like the engine. Options: `--delay-ms`, `--drop-every`, `--batch`, `--layer network\|forward`, `--priority`, `--queue-length`, `--queue-time-ms` (queue defaults match `backends/windivert/backend.cc`). |
| `bench.ps1` | Runs baseline, `hold0`, `hold0-batch` (16) and `hold2ms` at each rate and prints one table. Needs an elevated shell. |

Build and run (elevated PowerShell, lagsw closed):

```powershell
xmake build wdbench
.\pocs\windivert_benchmark\bench.ps1 -Pps 20000,100000 -Size 64 -Seconds 5
.\pocs\windivert_benchmark\bench.ps1 -Pps 20000,100000 -Size 1200 -Seconds 5
```

### Linux: `pocs/linux_kernel_module_backend`

`swbench` (flood, sink, sniff and hold modes) driven by `bench.py` in throw-away user and network namespaces
(client, gateway, server over `veth`). Same payload layout as `wdbench` (timestamp, then sequence number). Defaults:
`--pps 20000,100000`, `--sizes 64,1200`, `--seconds 5`, `--runs 3`. `swdiv` needs the module loaded and real root.

```
xmake build swbench swdivert
python3 pocs/linux_kernel_module_backend/bench.py --check
python3 pocs/linux_kernel_module_backend/bench.py --modes baseline,afpacket,nfq --pps 20000,100000
sudo python3 pocs/linux_kernel_module_backend/bench.py --pps 20000,100000      # includes swdiv
```

### Reading driver vs. interface

| Column (Windows) | Meaning | Points at |
|---|---|---|
| `cap_*` | sender stamp to `WinDivertRecv` returning | driver: stack, filter, queue, wake-up |
| `send_*` | duration of the `WinDivertSend` call | driver: re-injection |
| `over_*` | verdict due time to `WinDivertSend` called | interface: our scheduling and queueing of the hold |
| `lat_*` | sender stamp to sink received | everything; compare with baseline |
| `reordered` | packets arriving after a later packet of the same stream | diversion side effect |
| `lost` | sent minus received | queue overflow or drop |

The Linux harness reports sink latency (p50, p99, max), loss, duplicates, reordering and the reader's CPU per packet.
It has no `cap_`/`over_`/`send_` split yet; adding one to `swbench` would make the driver-versus-interface split
comparable. Timestamps use `QueryPerformanceCounter` on Windows and `CLOCK_MONOTONIC` on Linux; both need sender and sink
on one machine.

## Differences between the two measurements (why they are not comparable yet)

| | Windows run | Linux results quoted below |
|---|---|---|
| Path | loopback, network layer, `outbound` | `veth` pair through a gateway namespace, forward hook |
| Payload | 64 and 1200 B | 200 B |
| Rates | 20,000 and 100,000 pps | 20 kpps and 50 kpps |
| Flows | one | one |
| Duration, runs | 5 s, one run per cell | 3 s, four runs (run 1 shown) |
| Build | release | release |
| Metrics | sink latency, loss, reordering, hold-thread split | sink latency, reader CPU per packet (loss and reordering reported only as "none lost") |
| Machine | one machine, sender spinning a core | one machine, 8 CPUs, Linux 7.2.11 |

## Results

All latencies are in microseconds.

### Windows: WinDivert (loopback, network layer)

#### 20,000 pps (results were the same at 64 B and 1200 B; ranges span both)

| Scenario | lat p50 | lat p99 | lat max | lost | reordered / 100k | cap p99 |
|---|---|---|---|---|---|---|
| baseline (no WinDivert) | 9-10 | 48-61 | 339-1030 | 0 | 0 | - |
| hold0 (resume at once) | 26-27 | 106-119 | 1121-1363 | 0 | 8-10 | 60-74 |
| hold0-batch (16) | 36 | 148-150 | 730-1377 | 0 | 5-8 | 100-101 |
| hold2ms (verdict 2 ms later) | 2024 | 2078-2088 | 3211-3788 | 0 | 0-1 | 32-42 |

The first console output was cut off after `cap_p99`, so `over_*`, `send_*` and the hold reader's CPU were not captured.
The table output was widened afterwards; rerun to fill those in. `cap_p99` values at 100,000 pps were not reliably
readable and are omitted.

#### 100,000 pps (saturated; not game-relevant)

| Scenario | received of 500k | lost | lat p50 | lat p99 | lat max |
|---|---|---|---|---|---|
| baseline | 500,000 | 0 | 9-10 | 28-68 | 194-312 |
| hold0 | 195k-209k | about 58-61% | 32.5k-41k | 49k-66k | 75k-92k |
| hold0-batch | 375k-392k | about 22-25% | 32.5k-41k | 32.6k-41.6k | 50k-52k |
| hold2ms | 346k-399k | about 20-31% | 1.8M-2.1M | 3.2M-3.7M | 3.2M-3.7M |

A single reader saturates at roughly 40-80k packets/s, and batching helps. These rows are also inflated by sharing one
machine between sender, sink and reader.

### Linux: NFQUEUE and swdivert (bare metal, `veth`, 200 B, one flow; run 1 of 4, from the kernel module PoC)

Latency is p50 / p99, followed by the reader's CPU per packet. This is the plain "hold and resume" case.

| Mode | 20 kpps | 50 kpps |
|---|---|---|
| no hold (baseline) | 4 / 24 | 4 / 17 |
| NFQUEUE, one verdict per packet | 11 / 32, 4.32 us CPU | 12 / 49, 3.26 us CPU |
| NFQUEUE, batched verdicts | 12 / 36, 4.58 us CPU | 13 / 66, 3.42 us CPU |
| swdivert, plain resume (`hold_wake_us=0`) | 10 / 38, 2.87 us CPU | 8 / 57, 1.56 us CPU |
| swdivert, `hold_wake_us=50` | 58 / 87, 2.25 us CPU | 57 / 92, 1.22 us CPU |
| swdivert, `hold_wake_us=250` | 115 / 288, 1.22 us CPU | 138 / 299, 0.82 us CPU |
| NFQUEUE, modify every packet | 13 / 35, 5.27 us CPU | 16 / 44, 4.29 us CPU |
| swdivert, modify every packet (`RESUME_MOD`) | 11 / 55, 4.11 us CPU | 9 / 49, 2.11 us CPU |

Across the four runs no row lost a packet and no modified packet arrived with wrong bytes. Reader CPU, NFQUEUE over
swdivert (mean): plain resume 1.55x at 20 kpps and 2.12x at 50 kpps; modify every packet 1.41x and 2.01x. The 20 kpps
rows vary by up to 30% between runs. Under overload in the earlier VM runs swdivert released packets unmodified (3-4%
at 100 kpps) while NFQUEUE lost 13-41% and queued for 180-300 ms.

### Side by side at the game-scale rate (20 kpps, plain divert-and-resume)

| Backend | Baseline p50 | Divert p50 | Added median | Divert p99 | Lost | Reordered | Source |
|---|---|---|---|---|---|---|---|
| WinDivert | 9-10 | 26-27 | about +17 | 106-119 | 0 | 8-10 per 100k | measured here (loopback, 64 and 1200 B) |
| NFQUEUE (one verdict) | 4 | 11 | about +7 | 32 | 0 | TODO (not recorded) | PoC doc (`veth`, 200 B) |
| swdivert (`wake_us=0`) | 4 | 10 | about +6 | 38 | 0 | TODO (not recorded) | PoC doc (`veth`, 200 B) |
| AF_PACKET | - | - | sniff only, cannot hold | - | - | - | PoC doc |
| stub | - | - | no packet access | - | - | - | - |
| tc/netem | - | - | not built | - | - | - | proposal |

Caution: the baselines differ (9-10 vs. 4 us) because the paths differ, so compare the **added** latency, not the
absolute value, and treat even that as indicative until the Linux side is rerun with the same payload, rate and metrics.

## Findings so far

1. At a game-scale rate the Windows driver and the hold logic add only microseconds (median about +17 us, p99 about
   +60 us, no loss). Holding for 2 ms adds about +24 us on the median and about +90 us at p99 on top of the 2 ms.
   Nothing in these results points at WinDivert or the hold logic as a source of millisecond-scale delay.
2. The Linux backends also add only microseconds in the existing results (NFQUEUE about +7 us, swdivert about +6 us at
   the median). On that evidence none of the Linux backends adds a delay of the size of a weapon-swap window either.
   If these hold up, the Linux symptoms (shotgun hit over sniper hit, occasional re-sync delay) are more likely caused
   by something other than the capture and verdict path: the host's network path or interface, ordering or reordering,
   or engine behaviour.
3. Diverting on Windows introduces a small amount of reordering at 20 kpps (5-10 per 100,000 packets) that the baseline
   does not have. A 2 ms hold nearly removes it (0-1). Reordering is the most plausible mechanism for a damage-type
   outcome changing, and **it has not been measured on Linux at all**, because the Linux harness does not report it for
   the hold modes in the quoted tables.
4. Throughput ceilings differ: a single WinDivert reader saturates around 40-80k pps on loopback, and NFQUEUE and
   swdivert were not saturated at 50 kpps on bare metal. The ceilings are not game-relevant but explain the high-rate
   rows.
5. None of this is evidence about the real path: neither side was measured through the host's forward layer with a
   client behind it, or through the ProtonVPN interface.

These findings are hypotheses to test, not conclusions.

## Open items (to complete on Linux)

- TODO: run the Linux harness with the same parameters as the Windows run and add a real Linux column to the side by
  side table, using `--sizes 64` and also `1200`:

  ```
  python3 pocs/linux_kernel_module_backend/bench.py --modes baseline,nfq,afpacket --pps 20000 --sizes 64 --seconds 5 --runs 3
  sudo python3 pocs/linux_kernel_module_backend/bench.py --modes swdiv --pps 20000 --sizes 64 --seconds 5 --runs 3
  ```
- TODO: record reordering and loss for the Linux hold modes (the `swbench` sink already counts reordering; make
  `bench.py` print it) so finding 3 can be tested.
- TODO: add a `cap_`/`over_`/`send_` style split to the Linux hold reader, to separate the kernel path from the
  user-space scheduling the way `wdbench hold` does.
- TODO: rerun the Windows side with `over_*`, `send_*` and CPU visible (the table is now wide enough), three repetitions
  per cell like Linux's `--runs 3`, so that 5-10 reordered packets per 100k can be told apart from noise.
- TODO: measure the real path. On the host, `wdbench hold --layer forward` (Windows) and the `backend` mode of `swbench`
  (Linux, the real `backends/kmod` backend) with a client behind it, with and without the diverter, and compare loss,
  reordering and delay.
- TODO: repeat with `-Dst <local interface IP>` on Windows and a real NIC on Linux, to take the NIC path instead of
  loopback or `veth`.
- TODO: isolate the sender on its own core, or send from a second machine, to remove the shared-CPU inflation.
- TODO: tie any measured reordering or delay back to the in-game symptoms (weapon swap, shotgun vs. sniper damage, re-sync
  delay) with a timestamped in-game trial; the benchmark alone does not show that.

## Limitations

- Windows: loopback only, single run per cell, one machine for all roles, 100k rows saturated.
- Linux numbers are quoted from another document with different payload, rates, duration and metrics.
- The tc/netem and eBPF/netlink backends are proposals or only partly built and have no latency data.
- The in-game symptoms are anecdotal.
- The `pps` column glitch and table truncation in the first printed Windows output were display bugs in `bench.ps1`
  (fixed afterwards); the values themselves were unaffected.
