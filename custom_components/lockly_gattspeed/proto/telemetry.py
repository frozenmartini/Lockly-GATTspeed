"""The `0x1A` diagnostics block -- lifetime counters and motor telemetry.

Named `telemetry` rather than `diagnostics` because the component already has a
`diagnostics.py`, which is Home Assistant's download-diagnostics hook and an
entirely different thing.

**The reply is parsed in tiers and a short one is valid.** The application
guards each block separately, so a lock that answers with only the first 38
bytes is not malformed -- it simply has nothing to say past that point. Every
field here is therefore optional, and `None` means "not in this reply" rather
than "zero".

Three fields are deliberately not interpreted. `ele` and the three
`motor_ele_*` are single bytes the application ships straight to analytics
without ever displaying or unit-labelling them; whether they are a current, an
index or something else is not decidable from the application, and calling
`motor_ele_average` a current would be an interpretation wearing a reading's
clothes. `temperature_record` is 24 bytes with no documented structure at all.
They are exposed as raw integers, and a consumer that wants to publish them
owes a hardware baseline first.

⚠️ **No vendor surface displays any of this, so none of it has an oracle.**
The owner checked the app on 2026-09-21: there is no error or failure count
anywhere in it. That matters more than it looks. The `0x94` event names and the
`0x1E` version fields were both checked against something the app renders, and
both checks found real errors -- two of nine event names had their direction
inverted, and the version encoding was wrong outright. Every name in this
module is in the position those were in *before* that check, and cannot be
taken out of it by a screenshot.

So the field names here are a reading of the application's identifiers, not a
confirmed meaning, and a counter called `finger_fail` is only known to be a
counter that moves. Nothing in the component consumes this module today. A
consumer that publishes these as facts -- especially a failure count, which
reads as a security signal -- needs hardware that exercises each counter
deliberately, not a green test run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ProtoError

MIN_LEN = 38
"""The first tier. Below this the application does not parse at all."""

FULL_LEN = 80
"""Every field this map knows about, through `sensorNgTimes`."""


class TelemetryParseError(ProtoError, ValueError):
    """The block was too short to hold even its first tier."""


def _u16(b: bytes, at: int) -> int | None:
    return int.from_bytes(b[at:at + 2], "little") if len(b) >= at + 2 else None


def _u8(b: bytes, at: int) -> int | None:
    return b[at] if len(b) > at else None


@dataclass(frozen=True)
class Telemetry:
    """Decoded `0x1A` block. `None` throughout means "not in this reply"."""

    # -- keypad and biometric attempt counters ---------------------------
    random_keyboard: int | None = None
    fixed_keyboard: int | None = None
    common_keyboard: int | None = None
    finger_success: int | None = None
    finger_fail: int | None = None

    # -- motor telemetry, uninterpreted ----------------------------------
    ele: int | None = None
    motor_ele_max: int | None = None
    motor_ele_min: int | None = None
    motor_ele_average: int | None = None
    temperature_record: tuple[int, ...] = ()
    """24 bytes, structure unspecified by the application. Not a temperature
    in any known unit -- the name is the vendor's."""

    # -- lifetime operation counters -------------------------------------
    open_times: int | None = None
    card_open_success: int | None = None
    card_open_fail: int | None = None
    oac_one_time_success: int | None = None
    oac_one_time_fail: int | None = None
    oac_time_success: int | None = None
    oac_time_fail: int | None = None
    doorbell_rings: int | None = None
    rf_success: int | None = None
    push_success: int | None = None
    push_time: int | None = None
    manual_unlock_times: int | None = None
    """⚠️ `OtherQueryCmd` calls this slot `sensorTimes` and then **overwrites
    it** two fields later with the real `sensorTimes`. The sibling parser for
    the same block (`LockStatusAndReportCmd`, which is this block shifted +62)
    names it `setManualUnlockTimes`, and every other slot in the two agrees
    name for name -- so the odd one out is the vendor's copy-paste bug, not
    the layout."""
    re_push_times: int | None = None
    sensor_times: int | None = None
    rain_mode_times: int | None = None

    # -- fault counters, all u8 ------------------------------------------
    finger_wrong: tuple[int, ...] = field(default=())
    """`fingerWrong1Times` .. `fingerWrong8Times`, one byte each.

    The application reads these with `DataUtils.t`, which is written for four
    hex characters; given two it degenerates to a plain u8 and the
    little-endian swap is a no-op. Reading them as u16 would consume the
    fault counters below them and report nonsense for both."""
    doorbell_ng: int | None = None
    rf_ng: int | None = None
    door_starter_ng: int | None = None
    sensor_ng: int | None = None

    @property
    def finger_attempts(self) -> int | None:
        """Successes plus failures, when both are present.

        The pairing is the point of reading this block at all: the access log
        records what the lock *did* and never what it refused, so a rejected
        finger exists only as an increment here."""
        if self.finger_success is None or self.finger_fail is None:
            return None
        return self.finger_success + self.finger_fail

    def to_log(self) -> dict[str, object]:
        """Counters only. The uninterpreted fields are reported as byte
        counts, not values, so nothing here implies a unit we cannot defend."""
        return {
            # Clean u16 attempt counters. Omitted from this dict until the
            # first live read, where their absence was the one thing that
            # could not be checked against the reply -- a logs file that
            # silently drops decoded fields is the failure this project keeps
            # paying for.
            "random_keyboard": self.random_keyboard,
            "fixed_keyboard": self.fixed_keyboard,
            "common_keyboard": self.common_keyboard,
            "open_times": self.open_times,
            "finger_success": self.finger_success,
            "finger_fail": self.finger_fail,
            "card_open_success": self.card_open_success,
            "card_open_fail": self.card_open_fail,
            "oac_one_time_success": self.oac_one_time_success,
            "oac_one_time_fail": self.oac_one_time_fail,
            "oac_time_success": self.oac_time_success,
            "oac_time_fail": self.oac_time_fail,
            "doorbell_rings": self.doorbell_rings,
            "rf_success": self.rf_success,
            "manual_unlock_times": self.manual_unlock_times,
            "sensor_times": self.sensor_times,
            "rain_mode_times": self.rain_mode_times,
            "finger_wrong": list(self.finger_wrong),
            "doorbell_ng": self.doorbell_ng,
            "rf_ng": self.rf_ng,
            "door_starter_ng": self.door_starter_ng,
            "sensor_ng": self.sensor_ng,
            "temperature_record_bytes": len(self.temperature_record),
        }


def parse_telemetry(plain: bytes) -> Telemetry:
    """Decode a decrypted, padding-stripped `0x1A` body.

    ⚠️ The caller must have classified the reply with **`code_len=3`**. This
    reply code is `0A1A01` -- the sub-index comes back too -- and reading it
    as two bytes shifts every field below by one, which produces plausible
    counters rather than an error.
    """
    if len(plain) < MIN_LEN:
        raise TelemetryParseError(
            f"diagnostics block is {len(plain)} bytes; the application's first "
            f"tier needs {MIN_LEN}. Shorter than that is a truncated reply, "
            "not a lock with less to say."
        )
    return Telemetry(
        random_keyboard=_u16(plain, 0),
        fixed_keyboard=_u16(plain, 2),
        common_keyboard=_u16(plain, 4),
        finger_success=_u16(plain, 6),
        finger_fail=_u16(plain, 8),
        ele=_u8(plain, 10),
        motor_ele_max=_u8(plain, 11),
        motor_ele_min=_u8(plain, 12),
        motor_ele_average=_u8(plain, 13),
        temperature_record=tuple(plain[14:38]),
        open_times=_u16(plain, 38),
        card_open_success=_u16(plain, 40),
        card_open_fail=_u16(plain, 42),
        oac_one_time_success=_u16(plain, 44),
        oac_one_time_fail=_u16(plain, 46),
        oac_time_success=_u16(plain, 48),
        oac_time_fail=_u16(plain, 50),
        doorbell_rings=_u16(plain, 52),
        rf_success=_u16(plain, 54),
        push_success=_u16(plain, 56),
        push_time=_u16(plain, 58),
        manual_unlock_times=_u16(plain, 60),
        re_push_times=_u16(plain, 62),
        sensor_times=_u16(plain, 64),
        rain_mode_times=_u16(plain, 66),
        finger_wrong=tuple(plain[68:76]),
        doorbell_ng=_u8(plain, 76),
        rf_ng=_u8(plain, 77),
        door_starter_ng=_u8(plain, 78),
        sensor_ng=_u8(plain, 79),
    )
