# Research note: Desync duration vs. lag duration in The Division (2016)

## Status

Preliminary empirical observation for defensive research. This note records a
reported relationship from controlled observations; it does not establish a
universal property of the game's networking implementation.

## Question

How does the duration of positional desync after a network impairment ends
relate to the duration of that impairment?

## Definitions

- **Lag duration** (`T_lag`): elapsed time for which the network impairment is
  active.
- **Desync duration** (`T_desync`): elapsed time from the end of that
  impairment until the observed position discrepancy has converged within a
  stated measurement tolerance.

Measure convergence from a consistent observer view and use the same
measurement tolerance across trials. If convergence is not observed before a
disconnect or the end of a trial, record the result as censored rather than
assigning an assumed duration.

## Current observation

The reported trials indicate that desync duration is shorter than the preceding
lag duration:

`T_desync < T_lag`

This was true for the observations summarized so far. "Always shorter" should
therefore be read as a provisional description of that sample, not a confirmed
rule for every lag duration, network condition, movement pattern, or server
state. No specific ratio or causal mechanism has been established. A future
trial with `T_desync >= T_lag` would disconfirm the literal always-shorter
claim.

## Cascading interval hypothesis

One reported case had an approximately 30-second impairment followed by about
25 seconds of positional desync. A proposed interpretation is that a
post-impairment desync interval might, under some conditions, become the
effective interval for a subsequent desync cycle. If that interpretation were
correct, successive intervals could cumulatively extend an apparent movement
discrepancy beyond the initial impairment, until a later interval becomes too
short to sustain or distinguish from ordinary reconciliation. This is a
hypothesis, not a demonstrated repeatable behavior: the single 30/25-second
observation does not establish that intervals chain, that movement remains
continuously accelerated, or that a particular minimum interval triggers a
reset. No cutoff or causal mechanism has been measured.

## Defensive measurement notes

In authorized, controlled testing, record `T_lag` and `T_desync` separately,
along with observer, position discrepancy, network conditions, movement state,
and any correction or disconnect event. To assess the cascading hypothesis,
record each interval independently and check whether an apparent next interval
is a new event or simply continuation of the previous server/client state
mismatch. Compare individual trials and the ratio `T_desync / T_lag`; do not
infer a fixed scaling law from a small sample. Keep unobserved convergence,
disconnects, and measurement uncertainty explicit in results. The purpose is
to characterize replication and reconciliation behavior, not to tune
interference against other players.

## Relation to the broader analysis

This duration question is separate from the unverified distance and hit
validation observations in
[division1_lag_switch_weapon_swap_analysis.md](division1_lag_switch_weapon_swap_analysis.md#L329).
A shorter post-impairment desync does not by itself establish a damage threshold
or explain missed hits.
