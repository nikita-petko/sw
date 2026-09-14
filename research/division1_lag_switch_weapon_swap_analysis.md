# Analysis: "Lag Switching" via Weapon-Swap Damage Desync in Tom Clancy's The Division (2016)

## Status

Research document. Describes a historical client-server networking exploit class
and how it maps onto the packet-manipulation primitives implemented by `lagsw`.
This document is for defensive research, detection, and mitigation purposes:
understanding the exploit is a prerequisite for building server-side validation
that rejects it.

## 1. Terminology

"Lag switch" originally referred to a specific piece of hardware (a physical
inline Ethernet switch or a software equivalent) used to cut or throttle a
player's own upstream connection on demand. Colloquial use has since drifted to
describe almost any exploit that leverages network delay, jitter, or packet loss
to gain an unfair advantage (rubber-banding through cover, warping past hit
detection, etc.). This document is concerned with the **original, narrow
meaning**: a timed interruption of the client's outbound packet stream used to
create a window in which the server's view of the world lags behind the
client's, and the specific variant that combines this with a **weapon swap**
to shift damage attribution from a low-damage weapon to a high-damage weapon.

## 2. The exploit as described

1. The attacker equips a low-damage/high-fire-rate weapon (e.g. a shotgun or
   SMG) and begins firing at a target.
2. Immediately before or during firing, the attacker delays or drops the
   outbound packets that carry the fire/hit events for that weapon (the "lag"
   part). These packets are held client-side (or on an intercepting device)
   rather than being lost; nothing is generated fraudulently, the legitimate
   traffic is merely queued.
3. While outbound traffic is being withheld, the attacker performs a weapon
   swap to a high-damage weapon (e.g. a sniper rifle) and this swap is either
   sent immediately or is not itself withheld.
4. The attacker then releases the queued packets (turns the "switch" back on,
   or the delay timer elapses). The previously queued fire/hit events arrive
   at the server in a burst, after the weapon-swap event has already been
   processed server-side.
5. If the server evaluates weapon damage using the **currently equipped
   weapon at the time the hit/fire packet is processed**, rather than the
   weapon that was equipped at the time the shot was actually fired
   client-side, the delayed low-damage shots are scored using the now-equipped
   high-damage weapon's damage table.

The net effect: shotgun-rate-of-fire hits, sniper-rifle damage-per-hit.

## 3. Why this is possible: client-authoritative timing assumptions

Games built with lag compensation (favor-the-shooter models) generally must
answer three questions for every reported hit:
- **Where** was the target at the time of the shot (client rewind /
  interpolation), and
- **What** weapon/ammo/stat state applies to the shot, and
- **When**, in the trusted server timeline, did the shot happen.

The Division 1 used a client-driven, event-based combat model typical of the
Snowdrop engine era: the client locally simulates firing (recoil, spread,
raycast/hit-scan) and sends discrete network messages such as "weapon fired",
"hit confirmed against entity X", and "weapon switched to slot Y". The server
is authoritative for damage resolution and health, but it must still trust
*some* subset of client-reported state to make lag compensation tolerable over
imperfect connections (rather than requiring perfect, jitter-free ordering).

The vulnerability arises from an **ordering/state-binding assumption**: if the
server resolves "what weapon dealt this damage" from **its own current belief
of the player's equipped weapon at packet-arrival time** — instead of from a
weapon identifier/timestamp embedded in and bound to the original fire event
— then reordering or delaying packets relative to a weapon-switch event
breaks the assumption. The server is not being fed false data; it is being fed
**true data out of the order it was generated**, and it fails to
re-establish that order (or fails to bind the weapon-context to the shot at
the moment of firing rather than the moment of processing).

This is a specific case of a broader class of network game vulnerabilities:
**state-binding-at-processing-time instead of state-binding-at-event-time**,
combined with a **client-controllable delivery schedule** (whether via a
software delay, a hardware lag switch, a malicious NAT/router, or a
man-in-the-middle packet queue).

## 4. Broader context: client leniency as the root architectural cause

The weapon-swap lag switch is not an isolated bug; it is one symptom of a
wider architectural pattern in The Division 1's netcode: **the server trusts
client-reported state far more than a hit-scan, competitive-adjacent shooter
can safely afford to.** The same trust model that lets a delayed fire packet
be resolved against the wrong weapon also enabled several other
contemporaneous exploits, which is useful corroborating evidence that the
root cause is systemic rather than a one-off oversight:

- **Position/teleport hacks.** Reports and public exploit writeups from the
  game's active period describe clients that could send arbitrary or barely-
  validated position updates, which the server would accept as authoritative
  or with only coarse plausibility checks (e.g. speed/distance-per-tick
  limits that were too permissive or easily bypassed by sending fewer, larger
  jumps). This is the same class of failure as the weapon-swap issue: the
  server treats a client-asserted piece of state (`I am at position X`) as
  ground truth instead of deriving or bounding it from a server-owned
  simulation.
- **RPM (rate-of-fire) manipulation.** Because weapon fire cadence was
  effectively driven by how frequently the client chose to emit fire/hit
  events (gated loosely by client-side cooldown logic rather than a strict
  server-enforced per-weapon interval with tolerance for jitter only), a
  modified or scripted client could emit fire events faster than the
  weapon's nominal RPM allowed, and the server would honor them as legitimate
  shots. This mirrors the weapon-swap exploit in that both rely on the server
  under-validating *when* a client is allowed to claim an action happened,
  not just *what* the action was.
- **Common thread.** In all three cases (teleport, RPM, weapon-swap lag
  switch) the server is missing the same category of control: a
  server-authoritative timeline against which client-asserted events
  (position, fire cadence, equipped weapon) are checked for physical/temporal
  plausibility before being trusted. Where such a timeline exists but is only
  loosely enforced (generous tolerances, no cross-checking between related
  event streams, no rewind-based replay against past state), clients retain
  enough leeway to manufacture advantageous orderings or rates without ever
  sending a single "invalid" packet in isolation.

This framing matters for mitigation design: patching the weapon-swap case in
isolation (e.g. adding a cooldown on weapon swaps while shots are in flight)
would only close one instance of a pattern. The systemic fix is the same one
described in Section 7 generally: bind every client-asserted event to
server-verified time and state, and validate new events against a replayable
history rather than only against the server's present-tense belief.

## 5. Preconditions for the exploit to work

For the weapon-swap lag-switch to register damage incorrectly, several
conditions generally must hold on the vulnerable server implementation:

1. **Per-shot weapon context is not cryptographically/structurally bound to
   the shot.** E.g. a "hit" packet only carries target ID + damage roll
   inputs, and the server looks up "attacker's current weapon" separately at
   resolution time, instead of the fire packet itself carrying
   `weapon_id + weapon_stat_snapshot`.
2. **The server accepts a burst of delayed packets and processes them using
   present-tense state** rather than replaying them against a rewound
   equipment-state timeline (equipment-aware lag compensation is rare; most
   lag compensation systems focus on *position*, not *loadout*).
3. **No monotonic per-weapon-slot sequence/timestamp validation** that would
   let the server notice "this fire event's client timestamp precedes the
   most recent weapon-switch event's timestamp, therefore it must be resolved
   against the previous weapon."
4. **Sufficient outbound delay budget** exists before the server times out /
   disconnects the client for latency, or before client-side prediction
   desyncs badly enough to be visually obvious to the victim or to trigger
   anti-cheat heuristics (e.g. large duplicate/burst packet arrival, PSN/ping
   spikes).
5. **The weapon swap itself is not throttled or rate-limited** in a way that
   would block a swap while shots are in flight.

## 6. Mapping the exploit onto `lagsw` primitives

`lagsw` is a WinDivert-based packet interception tool that can hold and
selectively release matched TCP/UDP packets. It is useful here purely as a
**model of the mechanism**, i.e. to reason about which of its features
correspond to which step of the exploit, for the purpose of writing detection
logic. Relevant existing option surface (see [`include/packet_engine.h`](../include/packet_engine.h)
and [`README.md`](../README.md)):

| Exploit step | Closest `lagsw` primitive |
| --- | --- |
| Hold outbound "fire"/"hit" packets while continuing to fire | `delay_mode: from_timestamp` with `windivert_options.outbound: true`, or `delay_mode: send_all_after_delay` to batch a window of shots |
| Let the weapon-swap packet go out immediately, unaffected | A narrower `filter` (e.g. matching payload size/opcode patterns typical of fire events) that excludes the swap packet, or a second concurrently-active profile with `disables` used to hand off between "hold fire events" and "pass everything else" |
| Release the held burst on demand | `mode: hold` or `mode: toggle` deactivation, which flushes the queue immediately (per README: "Deactivation flushes all remaining packets immediately") |
| Avoid the server discarding stale/duplicate retransmissions | `retransmission_mode` set to `none` so TCP retransmissions of the same held segment are not deduplicated away, i.e. exactly reproducing "what a lossy real connection would also deliver" |
| Selectively affect only the game/session traffic | `global_filter` / per-profile `filter` scoped to the game server's `discovery_port`/known server IPs, and `client_address_enforcement` to avoid affecting unrelated local traffic |

This mapping illustrates the general point: **the exploit does not require any
packet forgery.** Every primitive listed only reorders or delays *legitimate,
unmodified* packets that the game client already produces. This is precisely
why the class of exploit is hard to block with payload validation or
signing alone — the payloads are correct; only their *arrival order relative
to other state transitions* is adversarial. This is also why WinDivert-style
tools (which only touch packets after the OS network stack, not before the
game encrypts/signs them) are sufficient to carry out the attack: it is a
transport-layer timing manipulation, not an application-layer forgery.

## 7. Why TCP vs UDP framing matters

If the game's combat channel runs over TCP, delaying an application-layer
message also delays the TCP segments carrying it, and holding one segment
can stall delivery of everything queued behind it on that stream (head-of-line
blocking) unless the game multiplexes logical channels over separate
connections or uses selective-ack-tolerant delivery. This makes the "release a
burst on demand" behavior easy to produce deliberately (as opposed to
naturally-occurring jitter, which rarely produces a clean, attacker-controlled
release point). If instead the combat channel is UDP-based, the same effect
requires the client (or an intercepting layer) to actually queue and reinject
packets, since the OS/network will not naturally hold UDP datagrams for you —
which is exactly the behavior a WinDivert-based interceptor provides, and
historically was the value proposition of physical "lag switch" hardware that
worked at the link layer below the OS entirely.

## 8. Detection and mitigation strategies (server-side)

These are the general classes of server-side countermeasures relevant to this
exploit family; they are described conceptually, not as code, since the
authoritative game server is not part of this repository:

1. **Bind weapon/ammo context to the fire event, not to processing time.**
   Every "shot fired" / "hit" message should embed the weapon slot, weapon
   instance ID, and relevant stat modifiers *as sampled at the moment of
   firing on the client*, and the server should use that embedded context for
   damage resolution rather than re-deriving "current weapon" from its own
   latest-known equip state.
2. **Sequence and timestamp fire events against equip-change events.** The
   server should maintain a small ordered log of recent equip-change events
   per player and validate/reject or re-attribute fire events whose client
   timestamp is provably older than the most recent accepted equip-change
   timestamp, especially when they arrive in a suspicious burst.
3. **Rate/interval sanity checks tied to weapon RPM.** A burst of "shotgun"
   shots that only makes sense at the shotgun's fire rate should not be
   payable as sniper-rifle damage even if it *arrives* clustered right after
   a swap; the server should recognize the rate-of-fire signature of the
   originating weapon independent of what is currently equipped.
4. **Burst/jitter heuristics.** A sudden burst of same-source hit
   confirmations following an artificially uniform gap (characteristic of an
   artificial hold-then-release) is a detectable network-timing signature
   distinguishable from organic jitter, which tends to be more variable and
   uncorrelated with equip-change events.
5. **Server-side re-simulation window ("lag compensation for loadout").**
   Extend traditional position-based rewind lag compensation to also rewind
   *equipped weapon state*, so that a late-arriving fire event is resolved
   against the equipment the target/attacker actually had at the rewound
   time, not the present tense.
6. **Anti-cheat / netcode telemetry.** Flag accounts whose outbound packet
   cadence shows repeated, deliberate stall-then-burst patterns correlated
   with weapon swaps — this is a strong behavioral signature that is unlikely
   to occur from ordinary network conditions.
7. **Apply the same discipline to every other client-asserted stream, not
   just weapons.** As Section 4 notes, position updates and fire-rate
   cadence suffer from the identical trust problem. Position deltas should be
   bounded against a server-simulated maximum displacement per tick derived
   from movement speed/abilities, and fire events should be checked against a
   server-tracked per-weapon cooldown rather than solely against a
   client-reported one, so that teleporting and RPM manipulation are closed
   by the same architectural change rather than three separate patches.

## 9. Empirical findings: conditions for consistently reproducing sniper damage

Hands-on testing while tuning the profiles in this repository (see
[`profiles/div1.yml`](../profiles/div1.yml)) found that the plain outbound
weapon-swap variant described in Section 2 is **not a fixed, deterministic
trigger** — whether the delayed low-damage shots register as the swapped-to
high-damage weapon is sensitive to several variables that are not obvious from
the exploit's basic description:

1. **Post-swap hold time must scale with how long fire was withheld, not be a
   fixed constant.** How long the sniper rifle must be held (i.e. how long the
   player must wait after swapping before releasing the delayed packets or
   swapping again) after the swap-to depends on the *duration of the prior
   lagging/withholding period*, not a single fixed value. A single withheld
   shot fired during a short delay window only needs a short post-swap hold;
   a longer burst (e.g. roughly ten shots) fired during a longer withholding
   period requires a proportionally longer post-swap hold before the server
   will resolve the pending shots against the newly-equipped weapon. This is
   consistent with the ordering-based root cause in Section 3: the server
   needs the swap event to be established (and, seemingly, to remain the
   "current" state for some minimum interval) before it will attribute a
   backlog of pending fire events to it, and a bigger backlog appears to need
   a longer window to be fully absorbed/attributed rather than partially
   attributed.
2. **Movement distance during the withholding period is also a factor.** How
   far the player moves (e.g. running away) between firing the withheld shots
   and releasing them influences whether the exploit lands, likely because
   large position deltas during the withheld window interact with the same
   position-based lag compensation/rewind system discussed in Section 4 —
   i.e. the server's hit-validation rewind has to reconcile both a stale
   position and a stale weapon simultaneously, and large movement makes that
   reconciliation more likely to reject the hit outright (independent of
   weapon attribution) rather than more likely to misattribute damage.
3. **The exploit can silently fail with no server-side hit at all.** In some
   attempts, the withheld shots do not appear to register as a hit on the
   target's screen under any weapon attribution — i.e. the failure mode is not
   always "correct weapon, correct damage" as a fallback, it can be "no shot
   registers visibly to observers," which suggests the server sometimes
   discards the ambiguous/stale burst entirely (e.g. because the accompanying
   rewind/position check fails, or because retransmission/sequence handling
   drops the packets as stale) rather than resolving it against either
   weapon.
4. **Even with correct timing, the technique is not 100% reliable.** Tuning
   the post-swap hold and withholding duration per Findings 1–2 improves
   consistency but does not make the exploit deterministic; some attempts
   still resolve as ordinary shotgun damage instead of sniper damage despite
   using the same timing that succeeded on a prior attempt, reinforcing that
   the server's attribution behavior is a race condition rather than a
   guaranteed outcome. In practice this is tolerable for the exploit's
   purpose: most players die to roughly one to two sniper-rifle hits, and
   since a shotgun blast is multiple pellets (commonly modeled as eight
   separate projectiles) each independently capable of inheriting the
   sniper's per-hit damage if the misattribution succeeds, a single withheld
   shotgun blast that lands as sniper damage typically delivers far more than
   enough hits/damage to kill even when only some pellets are misattributed,
   which is why the exploit remains effective in practice despite not being
   fully reliable on any single attempt.

These findings indicate that a workable exploit profile cannot use a single
fixed `delay_ms` and an instantaneous release; it needs the hold time *after*
the weapon swap to be tunable independently of the capture delay, and ideally
tunable per attempt based on how much was queued and how long the withholding
period lasted. This observation is what motivated the recent profile changes
in this repository (see [`profiles/div1.yml`](../profiles/div1.yml)):
separating the "withhold fire events" profile (`RPM`, `from_timestamp`) from
the long-hold profiles (`Long (Recv)` / `Long (Send)`, `ratio`-based with a
large `delay_ms` and partial percentage release), so that the post-swap hold
duration and the release fraction can be tuned and triggered independently of
the initial capture delay, rather than being coupled to a single fixed delay
value as a naive implementation would require.

## 10. Ethical and legal scope

This document analyzes a historical, publicly discussed exploit for
educational/defensive purposes (informing detection and mitigation design). It
does not include instructions for targeting Ubisoft's live game servers, does
not include any live server IP/port information beyond what is already present
elsewhere in this repository's example profiles, and should not be used to
violate a game's Terms of Service or applicable computer-fraud laws. Any use of
`lagsw` against production game infrastructure without authorization is out of
scope and not endorsed by this document.

## 11. Summary

The Division 1 weapon-swap lag switch is a textbook example of an **event-
ordering exploit**: it requires no packet forgery, only the ability to control
*when* legitimately-generated packets are delivered relative to other state
transitions (here, a weapon swap). The fix is architectural on the server —
binding damage resolution to event-time state rather than processing-time
state — not something that can be patched purely by filtering "bad" packets,
since the packets involved are indistinguishable from normal traffic in
isolation; only their timing relative to other events reveals the exploit.
