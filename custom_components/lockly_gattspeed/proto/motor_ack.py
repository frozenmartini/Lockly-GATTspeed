"""Parser for the 0x22 / 0x52 motor acknowledgement.

25 bytes on the wire, 16 plaintext, **4 bytes of actual payload** once padding
is off.

The single most important thing in this file is what is *not* here.

**There is no bolt position in the motor ACK.** The byte that follows the
event id is the padding marker `0x0B`, and it is identical for LOCK and
UNLOCK. Reading it as a state byte is the bug that made a successful LOCK
publish UNLOCKED on a real front door. An ACK says "the command was accepted",
never "the bolt is now here" -- so every motor command is followed by a
confirming status read.
"""

from __future__ import annotations

from .errors import ProtoError

from dataclasses import dataclass
from enum import IntEnum


class MotorResult(IntEnum):
    """Byte 0 of the ACK payload."""

    SUCCESS = 0x00
    REJECTED = 0x02
    """Refused by the lock -- welcome mode is the known cause. The bolt did
    not move, but treat the position as unknown and read status once: it is a
    refusal, not a report."""

    @classmethod
    def describe(cls, value: int) -> str:
        try:
            return cls(value).name.lower()
        except ValueError:
            return f"failure_0x{value:02x}"


PAYLOAD_LEN = 4
"""result, door bitfield, and a big-endian u16 event id."""

DOOR_FLAG_WIRED_SENSOR = 0x01
DOOR_FLAG_BOLT_UNLOCKED = 0x02
"""Byte 1 uses the same bitfield layout as status byte 4.

Measured 2026-09-20 over fifteen motor commands across three supervised runs:
every UNLOCK ACKed with `door_flags=3` and every LOCK with `door_flags=1`,
without exception. That is bit 0 always set -- the wired-sensor circuit, which
reads 1 with no sensor fitted, exactly as in the status reply -- and bit 1 set
when unlocked.

**It is still not a bolt position, and there is deliberately no `locked`
property on `MotorAck`.** Four reasons, none of which depend on timing:

1. **These bits are sent by the command handler, not read from the bolt.**
   They say what the lock agreed to do. Nothing in the ACK path consults the
   position sensor.
2. **A rejected command still carries them.** `result=0x02` is a refusal and
   the bolt did not move -- but `door_flags` is populated regardless, so
   publishing it would report a position for a command that never happened.
3. **This is how the original bug looked.** Byte 4 of the *unstripped*
   plaintext is the `0x0B` padding marker, identical for LOCK and UNLOCK, and
   reading it as a state byte once published UNLOCKED on a successful LOCK. A
   `locked` property invites the same class of mistake with better-looking
   bytes, which is worse than making it with none.
4. **One authority.** A status read consults the bolt; the ACK does not. Two
   sources of truth for a front door's state is a bug generator.

**On timing, which used to be the stated reason and is withdrawn.** This
docstring claimed the ACK arrives ~2.2 s in while the bolt does not report for
~5.0 s, so the bits demonstrably predate the bolt. That 5.0 s came from an
instrument that slept a fixed 2 s and then took one reading; polling from t=0
on a persistent subscription measures ACK ~1.8 s and a confirmed bolt ~2.4 s.
In five of six commands the **first** confirming read already saw the new
position, so this instrument cannot separate bolt arrival from ACK arrival at
all. The timing is not evidence in either direction. The four reasons above do
not need it.
"""

_RESULT = 0
_DOOR_FLAGS = 1
_EVENT_ID = slice(2, 4)


class MotorAckParseError(ProtoError, ValueError):
    """The payload is not a motor ACK we can trust."""


@dataclass(frozen=True)
class MotorAck:
    result: int
    event_id: int
    door_flags: int

    @property
    def accepted(self) -> bool:
        return self.result == MotorResult.SUCCESS

    @property
    def rejected(self) -> bool:
        return self.result == MotorResult.REJECTED

    def to_log(self) -> dict[str, object]:
        return {
            "result": self.result,
            "result_name": MotorResult.describe(self.result),
            "event_id": self.event_id,
            "door_flags": self.door_flags,
        }

    def __str__(self) -> str:
        return f"MotorAck({self.to_log()})"


def parse_motor_ack(plain: bytes) -> MotorAck:
    """Decode a decrypted, padding-stripped motor ACK payload.

    `plain` must already have had padding removed. If it is 16 bytes long the
    caller skipped the strip -- that is the shape of the historical bug, so it
    is rejected loudly rather than parsed.
    """
    if len(plain) != PAYLOAD_LEN:
        raise MotorAckParseError(
            f"motor ACK payload is {len(plain)} bytes, expected {PAYLOAD_LEN}"
            + (
                " -- looks like padding was not stripped; byte 4 is the 0x0B "
                "pad marker, not a bolt-position byte"
                if len(plain) == 16
                else ""
            )
        )
    return MotorAck(
        result=plain[_RESULT],
        door_flags=plain[_DOOR_FLAGS],
        # Big-endian, alone among this protocol's multi-byte integers, which
        # are otherwise little-endian. Reading it LE gives a plausible-looking
        # wrong number that only diverges once the counter passes 255.
        event_id=int.from_bytes(plain[_EVENT_ID], "big"),
    )
