# PoC: `send_all_after_delay` packet mode

## Status and scope

**Implemented:** the first packet starts a batch timer; packets captured before
release join that batch and are released together after `delay_ms`. A later
batch starts its own timer. A zero delay holds packets until flush.

## Phases

1. **Complete — batch timer:** schedule the batch relative to its first packet.
2. **Complete — lifecycle:** release the batch in receive order and flush
   remaining packets on deactivation.
3. **Proposed — burst characterization:** measure release spread and queue
   growth for varying packet rates on supported backends.

## Reproducible check

Run `xmake build modes_test && xmake run modes_test send_all_after_delay`.
[modes_test.cc](../tests/modes/modes_test.cc) checks timer boundaries, a
second batch, and zero-delay flush. Live trials must use authorized, isolated
traffic.

Implementation: [send_all_after_delay.cc](../src/packet_mode/send_all_after_delay.cc).
