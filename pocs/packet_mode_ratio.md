# PoC: `ratio` packet mode

## Status and scope

**Implemented:** a positive count releases that many queued packets per
`delay_ms` interval. A percentage selects a rounded-up fraction of the queue,
at least one when nonempty, at each interval; `ratio_selection` chooses
`first`, `last`, or `random`. Percentage ratios require a positive delay and
cannot exceed 100%. Deactivation flushes the remainder.

## Phases

1. **Complete — count scheduling:** assign successive groups to successive
   deadlines; an empty queue starts a new batch.
2. **Complete — percentage selection:** support rounding, selection policies,
   and repeated release of the remaining queue.
3. **Proposed — load study:** quantify queue growth and release intervals for
   sustained input; compare count and percentage policies without claiming
   random selection is reproducible across runs.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test ratio`. The fake-clock
cases in [modes_test.cc](../tests/modes/modes_test.cc) cover count intervals,
percentage rounding, selection, and minimum-one behavior. Use authorized,
isolated traffic for live measurements.

Implementation: [ratio.cc](../src/packet_mode/ratio.cc); configuration:
[README](../README.md#delay-modes).
