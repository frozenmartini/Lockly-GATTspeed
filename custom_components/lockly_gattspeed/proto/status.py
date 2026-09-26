"""Parser for the 0x1E status reply.

Offsets are into the **decrypted, padding-stripped** payload: 121 bytes on the
wire are 9 of framing plus **112 of ciphertext**, and stripping the inbound
padding marker leaves **104 of payload**. The two numbers are easy to conflate
and this docstring did, giving 112 as the payload length; every offset below
indexes into the 104. Offsets are read from the application; the values at them
are confirmed against a real lock over 1,657 polls.

Two of these fields are why this integration is a rewrite rather than a port.
The battery offset and the door-sensor bit are both wrong in the fork's
upstream, and both were wrong in a way that looked plausible.
"""

from __future__ import annotations

from .errors import ProtoError

from dataclasses import dataclass, field

# Offsets into the decrypted, padding-stripped payload.
_FIRMWARE = slice(0, 4)
_FLAGS = 4
_BATTERY_PCT = 7
_BATTERY_FLAG = 8
_CLOCK = slice(9, 15)
_AUTOLOCK_DELAY = slice(16, 18)
_LOCK_TYPE = 18
_NONCE = slice(19, 27)
_SOLAR_MV = slice(84, 86)
_BLE_VERSION = slice(86, 90)
_AUTOLOCK_CHECKS_SENSOR = 90

MIN_LEN = 91
"""Everything v1 reads lives below byte 91. Shorter than this is not a status
reply, whatever the cmd type claimed."""

BATTERY_UNAVAILABLE = 0xF1
"""Byte 8. Checked **before** byte 7 -- when this is set the percent byte is
not a reading, and publishing it would show a confident wrong number."""

# Byte 4, the status bitfield.
_BIT_WIRED_SENSOR = 0
_BIT_BOLT = 1
_BIT_WIRELESS_SENSOR = 2
_BIT_INVALID_VOLTAGE = 4


class StatusParseError(ProtoError, ValueError):
    """The payload is not a status reply we can trust."""


def _decimal_pairs(data: bytes) -> str:
    """Each byte is its own **decimal** value, zero-padded to two digits.

    Correct for the clock (`26 09 14` -> "260914", year 2026) and for the lock
    type (0x69 -> 105). ⚠️ **Not** correct for the version fields, which look
    similar and are not -- see `_version`.
    """
    return "".join(f"{b:02d}" for b in data)


def _version(data: bytes) -> str:
    """A 4-byte version field: `b[3].b[2].b[1]`, as **hex digit pairs**.

    The application parses the decrypted reply as a hex *string* and slices
    characters out of it, so a version component is the two hex characters
    themselves -- BCD in practice -- and not the byte's decimal value. It also
    reads them **backwards** and drops `b[0]` entirely
    (`ble-opcode-table-reharvest.md`, `QueryLockStatusCmd:169-171`).

    Proved against the vendor app's own About page, 2026-09-21. Four of the
    five versions it publishes are in this reply and each appears at exactly
    one offset under this rendering and none under any other:

        bytes  0-3   1.00.91   "Front Panel Version"   (main board)
        bytes 68-71  1.00.76   "Back Panel Version"    (sub board)
        bytes 76-79  2.02.72   "Wi-Fi Version"
        bytes 86-89  1.14.28   "Bluetooth Version"

    The fifth -- the app's headline "Version 1.14.31" -- is not in this reply
    under any offset, so it is not ours to report and is not guessed at here.

    ⚠️ This shipped as `_decimal_pairs` until 2026-09-21 and put "001450001"
    on the device page where the app says 1.00.91. The unit fixture had been
    built from the same misreading, so it agreed; the golden frame from the
    real lock was never checked against a published number. Non-BCD nibbles
    would surface as hex letters, which is the honest failure.
    """
    return f"{data[3]:x}.{data[2]:02x}.{data[1]:02x}"


def _le16(data: bytes) -> int:
    return int.from_bytes(data, "little")


@dataclass(frozen=True)
class Status:
    """A decoded 0x1E reply.

    `to_log()` is the only representation that may be written to a logs file
    or a diagnostics dump; the nonce never appears in either.
    """

    firmware: str
    locked: bool
    battery_percent: int | None
    battery_unavailable: bool
    invalid_voltage: bool
    lock_clock: str
    autolock_delay_s: int
    lock_type: int
    solar_mv: int
    ble_version: str
    autolock_checks_door_sensor: bool

    wired_sensor_bit: bool
    wireless_sensor_bit: bool
    """Both door-sensor bits are parsed and **neither is exposed as an entity
    on lock type 105.** Bit 0 reads 1 with no sensor fitted, so it is not a
    door state; bit 2 is unverified on this hardware. Kept for diagnostics
    and for models that do have a sensor."""

    nonce: bytes = field(repr=False, default=b"")
    """Cached for models that need it in later commands. Never logged, never
    included in `to_log()`, excluded from `repr`. Lock type 105 takes the
    timestamp branch and never uses this."""

    def to_log(self) -> dict[str, object]:
        """Safe-by-construction projection for logs and diagnostics."""
        return {
            "firmware": self.firmware,
            "locked": self.locked,
            "battery_percent": self.battery_percent,
            "battery_unavailable": self.battery_unavailable,
            "invalid_voltage": self.invalid_voltage,
            "lock_clock": self.lock_clock,
            "autolock_delay_s": self.autolock_delay_s,
            "lock_type": self.lock_type,
            "solar_mv": self.solar_mv,
            "ble_version": self.ble_version,
            "autolock_checks_door_sensor": self.autolock_checks_door_sensor,
            "wired_sensor_bit": self.wired_sensor_bit,
            "wireless_sensor_bit": self.wireless_sensor_bit,
            "nonce_len": len(self.nonce),
        }

    def __str__(self) -> str:  # never let a bare print leak the nonce
        return f"Status({self.to_log()})"


def parse_status(plain: bytes) -> Status:
    """Decode a decrypted, padding-stripped 0x1E payload."""
    if len(plain) < MIN_LEN:
        raise StatusParseError(
            f"status payload is {len(plain)} bytes, need at least {MIN_LEN}"
        )

    flags = plain[_FLAGS]
    unavailable = plain[_BATTERY_FLAG] == BATTERY_UNAVAILABLE

    return Status(
        firmware=_version(plain[_FIRMWARE]),
        # bit 1: 1 means UNLOCKED. Cross-checked on hardware, where the app's
        # own A1/A3 status bytes track it: 0xA1 LOCKED, 0xA3 UNLOCKED.
        locked=not (flags >> _BIT_BOLT) & 1,
        battery_percent=None if unavailable else plain[_BATTERY_PCT],
        battery_unavailable=unavailable,
        invalid_voltage=bool((flags >> _BIT_INVALID_VOLTAGE) & 1),
        lock_clock=_decimal_pairs(plain[_CLOCK]),
        # The app calls this `autoUnLockTime`. It is the auto-**LOCK** delay.
        # The name is a trap and has already cost someone a wrong entity.
        autolock_delay_s=_le16(plain[_AUTOLOCK_DELAY]),
        # Plain integer, not decimal-pair encoded: 0x69 is 105.
        lock_type=plain[_LOCK_TYPE],
        solar_mv=_le16(plain[_SOLAR_MV]),
        # Bytes 27..30 hold *a* BLE module version. It is not this one, and
        # upstream reads that one. The real version is at 86..89.
        ble_version=_version(plain[_BLE_VERSION]),
        autolock_checks_door_sensor=bool(plain[_AUTOLOCK_CHECKS_SENSOR]),
        wired_sensor_bit=bool((flags >> _BIT_WIRED_SENSOR) & 1),
        wireless_sensor_bit=bool((flags >> _BIT_WIRELESS_SENSOR) & 1),
        nonce=bytes(plain[_NONCE]),
    )
