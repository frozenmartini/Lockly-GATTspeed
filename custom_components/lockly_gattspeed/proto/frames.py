"""Request frame construction, and the opcode allow-list.

**The allow-list is the only safety gate in this integration.** The transport
carries opaque encrypted bytes and can enforce nothing; the lock will happily
factory-reset itself if asked. `0x0F` (delete lock), `0x10` (factory reset)
and `0x1D` (reset BLE module) sit numerically adjacent to `0x11`, `0x12` and
`0x1E`, so an off-by-one in an opcode table is a factory reset on a front
door. Allow-list, never deny-list.

Frame layout, verified against `Cmd.addBleData`:

    [0..3]    A1 B2 C3 D4
    [4..5]    total frame length, LE16 -- counts the WHOLE frame
    [6..6+N)  AES-128-ECB ciphertext (the opcode lives inside it)
    [6+N]     metadata = (pad_bytes << 4) | encrypt_type
    [7+N]     CRC-8 over every preceding byte

**Outbound padding is bare zeros and carries no marker.** The pad length
travels out-of-band in the metadata byte's high nibble. Inbound padding is the
opposite -- self-describing via `0x0N`/`0xF0`, with no metadata byte on the
reply at all. That asymmetry is the easiest thing in this protocol to get
wrong, so the two directions live in different modules on purpose.
"""

from __future__ import annotations

from .errors import ProtoError

import time
from dataclasses import dataclass

from .caps import Capabilities
from .crypto import (
    BLOCK,
    aes_ecb_encrypt,
    crc8,
    derive_key,
    encrypt_master_code,
)

MAGIC = bytes((0xA1, 0xB2, 0xC3, 0xD4))
HEADER_LEN = 6
TRAILER_LEN = 2  # metadata byte + CRC

OP_STATUS = 0x1E
OP_MOTOR_LEGACY = 0x22
OP_MOTOR = 0x52
OP_DIAGNOSTICS = 0x1A
OP_ACCESS_LOG = 0x94
OP_TIMEZONE = 0x33

ALLOW: frozenset[int] = frozenset(
    {OP_STATUS, OP_MOTOR_LEGACY, OP_MOTOR, OP_ACCESS_LOG, OP_DIAGNOSTICS,
     OP_TIMEZONE}
)
"""Every opcode this integration may ever put on the wire.

Five, not seven. v1 was lock/unlock, status and battery; `0x94` was added for
the access log, which is a **read** -- it moves nothing and writes no lock
state. `0x7C` is deliberately still out: it is the same command for a
different model family, its record layout differs in the middle four bytes
only, and a 0x7C page parsed as 0x94 (or the reverse) produces plausible
records with a wrong `pwdId` and no error anywhere. `0x34` and `0x1A` remain
out -- `0x1A` no longer is: it is a pure read on the code path the app
itself uses for this model, and `0x34` stays out because the research's
own verdict is not to send it to a front door.

**`0x33` is the one entry here that is a write opcode in the application,
and it is admitted in its read form only.** `SetTimeZoneCmd` carries an
action byte: `1` sets the lock's timezone, `2` asks what it is. Only
`build_timezone_query` exists, it hardcodes `2`, and there is deliberately
no builder that can emit `1` -- so no argument, no typo and no future
caller can change the owner's lock timezone through this package. Admitted
2026-09-21 on the owner's instruction, because the log's timestamps are
stamped in whatever offset was last written to the lock and nothing else
we can read reports that offset.
"""

NEVER_SEND: dict[int, str] = {
    # -- destructive: irreversible, or bricks the lock --------------------
    0x08: "OTA version check -- the entry point to the OTA flow",
    0x0E: "OTA firmware image chunk",
    0x0F: "delete/unpair the lock",
    0x10: "factory reset and restart",
    0x1D: "reset the BLE module -- drops the link this integration holds",
    0x30: "dual-MCU OTA firmware chunk",
    0x3F: "firmware upgrade of the light module",
    0x6B: "select which MCU the next OTA targets -- arms the OTA path",
    # -- changes the master code: invalidates the derived AES key ---------
    0x01: "change master code (sub-command 01 or 04)",
    # -- deletes credentials: irreversible loss of user data --------------
    0x02: "delete a guest PIN (legacy form, sub-command 03)",
    0x16: "delete an enrolled fingerprint or card",
    0x37: "unpair a paired light",
    0x3E: "delete an enrolled credential (new form)",
    0x4D: "delete a credential by user number",
    0x80: "bulk-delete every RF credential",
    0x83: "replace the sub-administrator",
    0xA6: "delete a guest PIN (166 form)",
    # -- leaves the door open, or disables verification -------------------
    0x43: "welcome mode -- a scheduled unlocked window",
    0x46: "always-open mode",
    0x4F: "how many factors an unlock requires -- silent security downgrade",
    0x8B: "welcome mode (newer form)",
    0x8E: "multi-user / two-factor unlock policy",
    0x8F: "duress-code behaviour",
    0x9B: "energy-saving welcome mode",
    # -- refused on other grounds -----------------------------------------
    0x39: "reads enrolled fingerprint templates off the lock in the clear",
    0x3A: "uploads a fingerprint template to the lock",
    0x49: "declares the mechanical lock type -- plausibly mis-drives the motor",
    0x98: "writes the household Wi-Fi SSID and passphrase into the lock",
}
"""Documentation and a test target, not a filter.

`build()` gates on `ALLOW`, so this dict changes nothing at runtime. It exists
so the test suite can assert that every one of these raises, and so the reason
each is dangerous is written down next to it.

**It is the full set from the research, not a sample.** Until 2026-09-20 this
dict held eight rows while `ble-opcode-table-reharvest.md` section 6 documented
every row below -- harmless while `ALLOW` was three read/motor opcodes, and
exactly the kind of gap that stops being harmless the first time somebody
widens the gate. Section 6 is the source; keep them in step, and prefer adding
a row here over trimming one.

**`0x10` is the row that matters, and it is easy to look past.** The project's
prose never-send list leads with `AT+SRESTART`, which is the loud name and the
wrong thing to guard: `windows` swept the whole APK on 2026-09-20 and found
that its sender, `ReStartCmd`, is **dead in this build**, that no literal
`AT+SRESTART` exists anywhere (it is concatenated at runtime from
`MessageManage.java:236` `AT = "AT+"`), and that a fifth verb `AT+SN` exists
with no caller. There is no `AT+` string in any of the 62 native libraries.

The command that actually factory-resets this lock is a framed binary opcode:
`0x10`, `ResetLockAndReStartCmd`, AES-encrypted with the master code, two real
callers. It is on this list and outside `ALLOW`, so it is unsendable twice
over -- but a reader should not come away thinking the AT verb was the danger.

`AT+SRESTART` is still absent from this dict because it is a raw ASCII string
rather than a framed command and cannot be expressed here at all. That remains
true and is now beside the point.
"""

# Payload field constants.
TRANSPORT_DIRECT_BLE = 0x00
TRANSPORT_HUB = 0x01

ROLE_HOST = 0x02
ROLE_LONG_TERM_OR_STAFF = 0x03

ACTION_UNLOCK = 0x01
ACTION_LOCK = 0x02


class OpcodeNotAllowed(ProtoError):
    """Refused by the allow-list. Never downgrade this to a warning."""

    def __init__(self, opcode: int) -> None:
        why = NEVER_SEND.get(opcode)
        detail = f" -- this opcode is {why}" if why else ""
        super().__init__(
            f"opcode 0x{opcode:02X} is not in the allow-list{detail}. "
            "Allowed: " + ", ".join(f"0x{o:02X}" for o in sorted(ALLOW))
        )
        self.opcode = opcode


class FieldError(ProtoError, ValueError):
    """A payload field is missing or the wrong width.

    Raised loudly and on purpose. The application *silently skips* a null or
    empty field, which shortens the frame by that field's width and leaves
    every later field misaligned. The lock then answers with an opaque `F3` or
    `FA` that reads like a credential problem, and the real cause -- one
    absent field -- is invisible. Every field here is mandatory.
    """


@dataclass(frozen=True)
class Creds:
    """Credentials fetched once from the cloud at config-flow time.

    Cacheable indefinitely: there is no TTL, no freshness check and no token
    on the command path. The only invalidator is the master code changing on
    the lock, which surfaces as F3/FA/FF.

    `__repr__` is redacted, and a dataclass's `__str__` defers to `__repr__`,
    so neither a bare print nor an f-string can leak these.
    """

    master_code: str
    uuid: bytes
    house_code: str = ""

    def __repr__(self) -> str:
        return (
            f"Creds(master_code=<{len(self.master_code)} digits>, "
            f"uuid=<{len(self.uuid)} bytes>, "
            f"house_code=<{len(self.house_code)} chars>)"
        )

    def to_log(self) -> dict[str, object]:
        return {
            "master_code_digits": len(self.master_code),
            "uuid_len": len(self.uuid),
            "house_code_len": len(self.house_code),
        }


def _field(value: bytes, name: str, width: int | None = None) -> bytes:
    if not value:
        raise FieldError(
            f"field {name!r} is empty; the app would silently drop it and "
            "shorten the frame, which the lock reports as an opaque F3/FA"
        )
    if width is not None and len(value) != width:
        raise FieldError(f"field {name!r} must be {width} bytes, got {len(value)}")
    return value


def _digit_bytes(code: str, name: str) -> bytes:
    """One byte per decimal digit, as the access code is carried."""
    if not code.isdigit():
        raise FieldError(f"{name} must be decimal digits")
    return bytes(int(c) for c in code)


def pad_len(payload_len: int) -> int:
    """Zero bytes appended to reach a block boundary.

    `(16 - n % 16) % 16` -- the outer modulo matters: an already-aligned
    payload gets **no** padding at all, not a full dummy block.
    """
    return (BLOCK - payload_len % BLOCK) % BLOCK


def assemble(fields: list[tuple[str, bytes]], key: bytes, encrypt_type: int) -> bytes:
    """Concatenate, pad, encrypt, frame, checksum."""
    # The allow-list gates the opcode the *caller asked for*. This checks the
    # opcode that is actually about to be encrypted, which is the one the lock
    # will act on. Without it the gate and the wire can disagree, and the gate
    # is the only safety mechanism this integration has.
    if not fields or fields[0][0] != "opcode" or len(fields[0][1]) != 1:
        raise FieldError("the first payload field must be a one-byte 'opcode'")
    emitted = fields[0][1][0]
    if emitted not in ALLOW:
        raise OpcodeNotAllowed(emitted)

    payload = b"".join(_field(v, n) for n, v in fields)
    pad = pad_len(len(payload))
    if not 0 <= pad <= 0x0F or not 0 <= encrypt_type <= 0x0F:
        # Both halves share one byte; either overflowing would silently
        # corrupt the other's nibble.
        raise FieldError(
            f"metadata byte would overflow: pad={pad}, encrypt_type={encrypt_type}"
        )

    ciphertext = aes_ecb_encrypt(key, payload + bytes(pad))
    total = len(ciphertext) + HEADER_LEN + TRAILER_LEN

    frame = bytearray(MAGIC)
    frame += total.to_bytes(2, "little")
    frame += ciphertext
    frame.append((pad << 4) | encrypt_type)
    frame.append(crc8(bytes(frame)))
    return bytes(frame)


def _preamble(creds: Creds, opcode: int,
              sub_index: int | None = None) -> list[tuple[str, bytes]]:
    """Opcode, optional sub-index, master-code length, obfuscated master code.

    `mcLen` counts **digits**, which is also the byte width of the field that
    follows it -- the lock uses it to find where the next field starts.

    **The sub-index goes second, before the length and not after it.** Every
    sub-indexed builder in the application has this shape -- `HexUtils.c("1A",
    "1", mcLen, encMC, nonce)` -- and putting it anywhere else moves the
    master code, which the lock reports as a credential error rather than as
    a malformed frame.
    """
    enc_mc = encrypt_master_code(creds.master_code, creds.uuid)
    fields = [("opcode", bytes((opcode,)))]
    if sub_index is not None:
        fields.append(("sub_index", bytes((sub_index,))))
    fields += [
        ("mc_len", bytes((len(creds.master_code),))),
        ("enc_master_code", enc_mc),
    ]
    return fields


def build_status(caps: Capabilities, creds: Creds, when: time.struct_time | None = None,
                 hub: bool = False) -> bytes:
    """0x1E -- query lock status.

    Five fields, and **no nonce and no millisecond timestamp**: the only
    time-like field is a wall-clock date in the lock's own timezone.
    """
    if OP_STATUS not in ALLOW:  # pragma: no cover - structural guard
        raise OpcodeNotAllowed(OP_STATUS)
    t = when or time.localtime()
    # Plain binary, not BCD: decimal 25 travels as 0x19. The app converts
    # deliberately, so a BCD reading here would be off by a lot on most dates.
    stamp = bytes((t.tm_year % 100, t.tm_mon, t.tm_mday,
                   t.tm_hour, t.tm_min, t.tm_sec))
    fields = _preamble(creds, OP_STATUS)
    fields += [
        ("datetime", _field(stamp, "datetime", 6)),
        ("transport", bytes((TRANSPORT_HUB if hub else TRANSPORT_DIRECT_BLE,))),
    ]
    return assemble(fields, derive_key(creds.master_code, creds.uuid),
                    caps.encrypt_type(OP_STATUS))


HOST_USER_ID = 0
"""The slot field's value for a host, and the only value proven on hardware.

`isOwner()` is defined as `userId == 0 && adminId == 0`, and nothing in the
application ever assigns a host a non-zero user id. **Sending 1 instead makes
the lock compare the access code against a different credential and reject it
with `FF`** -- which reads as "wrong password" and sends you looking in the
wrong place entirely.
"""


def build_motor(caps: Capabilities, creds: Creds, *, lock: bool, access_code: str,
                user_id: int = HOST_USER_ID, now_ms: int | None = None,
                hub: bool = False) -> bytes:
    """0x52 (or legacy 0x22) -- operate the bolt.

    Field 4 is the **requester role**, not the action -- it is 0x02 for a host
    and 0x03 for a long-term guest or staff, and it does not change between
    locking and unlocking. The action is field 7. The app's own name for
    field 4 is `unLockType`, which is why this is worth spelling out.
    """
    opcode = caps.motor_opcode()
    if opcode not in ALLOW:  # pragma: no cover - structural guard
        raise OpcodeNotAllowed(opcode)

    if not 0 <= user_id <= 0xFFFF:
        raise FieldError(f"user_id {user_id} does not fit in the 2-byte slot field")

    ms = now_ms if now_ms is not None else int(time.time() * 1000)
    fields = _preamble(creds, opcode)
    fields.append(("requester_role", bytes((ROLE_HOST,))))
    fields.append(("access_code", _digit_bytes(access_code, "access_code")))

    if caps.wide_slot_field:
        # The cloud access-user id, not the password slot: isSupportAccessUser()
        # is true for this model, which selects getUserId() over getPwdIdInt().
        fields.append(("user_id", user_id.to_bytes(2, "little")))
    else:
        if not 0 <= user_id <= 0xFF:
            raise FieldError(
                f"pwd_id {user_id} exceeds 255; the legacy 0x22 slot is one byte "
                "and the app misaligns the frame above that"
            )
        fields.append(("pwd_id", bytes((user_id,))))

    fields.append(("action", bytes((ACTION_LOCK if lock else ACTION_UNLOCK,))))
    fields.append(("transport", bytes((TRANSPORT_HUB if hub else TRANSPORT_DIRECT_BLE,))))

    if caps.supports_timestamp:
        # 8 bytes, little-endian, milliseconds since the Unix epoch. This is
        # the entire anti-replay story, which is why the README has to
        # disclose that a captured frame is plausibly replayable.
        fields.append(("timestamp", ms.to_bytes(8, "little")))
    else:
        raise FieldError(
            "this model needs the cached nonce rather than a timestamp, which "
            "v1 does not implement -- no v1 model takes that branch"
        )

    return assemble(fields, derive_key(creds.master_code, creds.uuid),
                    caps.encrypt_type(opcode))


DATE_UNLIMITED = b"\xff\xff\xff"
"""`yyMMdd` sentinel meaning "no lower/upper bound" -- `PagingLogCmd.java:32`."""

DATETIME_UNLIMITED = b"\xff\xff\xff\xff\xff"
"""`yyMMddHHmm` sentinel, the same idea five bytes wide -- `:31`."""


def _log_window(when: time.struct_time | None) -> tuple[bytes, bytes]:
    """One window bound as the (3-byte date, 5-byte datetime) pair it travels as.

    The request carries the *same* bound twice, at two resolutions, from the
    same source value -- `getDate` formats `yyMMdd` and `getDateTime` formats
    `yyMMddHHmm` from one millisecond argument (`PagingLogCmd.java:110-116`).
    They are redundant to each other and which one the firmware honours is not
    readable from the application, so both are always sent.
    """
    if when is None:
        return DATE_UNLIMITED, DATETIME_UNLIMITED
    yy, mm, dd = when.tm_year % 100, when.tm_mon, when.tm_mday
    # Plain binary, exactly as `build_status` -- decimal 25 travels as 0x19.
    return (bytes((yy, mm, dd)),
            bytes((yy, mm, dd, when.tm_hour, when.tm_min)))


def build_access_log(caps: Capabilities, creds: Creds, *, nonce: bytes,
                     cursor: int = 1,
                     start: time.struct_time | None = None,
                     end: time.struct_time | None = None) -> bytes:
    """0x94 -- read one page of the access log.

    A read. It moves nothing and writes no lock state.

    **The cursor sits in the middle of the frame, between the two date fields
    and the two datetime fields.** That ordering is not a mistake and not
    negotiable: `HexUtils.c` silently skips empty arguments, so a builder that
    omits an unused window rather than sending the `FF` sentinels shifts the
    cursor two bytes left and every later field with it. The lock answers that
    with an opaque `F3`/`FA` that reads like a credential problem. `_field`
    refuses an empty field for the same reason.

    `cursor` is a **1-based ordinal into the matching set**, not a page number
    -- the app advances it to `curSum + 1`, where `curSum` is the cumulative
    record count from the reply header (`RxLog124CmdDataSource.java:37,60`).

    `nonce` is the 8 bytes cached from the most recent `0x1E` status reply.
    There is no other source: nothing else on this lock refreshes it, and it
    has no expiry, no consumed flag and no invalidation anywhere.
    """
    if OP_ACCESS_LOG not in ALLOW:  # pragma: no cover - structural guard
        raise OpcodeNotAllowed(OP_ACCESS_LOG)
    if not caps.supports_148_cmd:
        # 0x7C is the other half of this fork and is deliberately outside
        # ALLOW. Refuse rather than substitute: the two record layouts differ
        # only in the middle four bytes, so the wrong one parses cleanly into
        # wrong answers.
        raise FieldError(
            f"lock type {caps.lock_type} ({caps.model}) does not use 0x94 for "
            "its access log; 0x7C is not implemented and not allowed"
        )
    if not 0 < cursor <= 0xFFFF:
        raise FieldError(
            f"cursor {cursor} is out of range; it is a 1-based LE u16 ordinal"
        )

    start_date, start_dt = _log_window(start)
    end_date, end_dt = _log_window(end)

    fields = _preamble(creds, OP_ACCESS_LOG)
    fields += [
        ("start_date", _field(start_date, "start_date", 3)),
        ("end_date", _field(end_date, "end_date", 3)),
        ("cursor", cursor.to_bytes(2, "little")),
        ("start_datetime", _field(start_dt, "start_datetime", 5)),
        ("end_datetime", _field(end_dt, "end_datetime", 5)),
        ("nonce", _field(nonce, "nonce")),
    ]
    return assemble(fields, derive_key(creds.master_code, creds.uuid),
                    caps.encrypt_type(OP_ACCESS_LOG))


SUB_DIAGNOSTICS = 0x01
"""`OtherQueryCmd` sends `1A` with sub-index 1. `1A`+`02` is a reply code with
no builder anywhere in the application -- presumably a heartbeat push -- and is
deliberately not reachable from here."""


def build_diagnostics(caps: Capabilities, creds: Creds, *, nonce: bytes) -> bytes:
    """0x1A sub-index 1 -- the diagnostics / daily-report block.

    A read. It moves nothing and writes no lock state.

    This is the block the application itself pulls from a type-105 lock:
    `DailyReportUtil` sends 0x34 only when `isSupportMerge()`, which is false
    here, and falls through to this instead. So it is an exercised path rather
    than one we discovered.

    Five fields, and the shortest payload of any command here. `nonce` is the
    8 bytes cached from the most recent `0x1E` reply; `OtherQueryCmd` reads it
    with no fallback, so there is no variant of this frame without one.
    """
    if OP_DIAGNOSTICS not in ALLOW:  # pragma: no cover - structural guard
        raise OpcodeNotAllowed(OP_DIAGNOSTICS)
    fields = _preamble(creds, OP_DIAGNOSTICS, SUB_DIAGNOSTICS)
    fields.append(("nonce", _field(nonce, "nonce")))
    return assemble(fields, derive_key(creds.master_code, creds.uuid),
                    caps.encrypt_type(OP_DIAGNOSTICS))


# -- 0x33, timezone ------------------------------------------------------

ACTION_TZ_QUERY = 0x02
"""`SetTimeZoneCmd.getQueryData` passes action 2. Action 1 *sets* the lock's
timezone and is never built here."""

ZONE_QUERY = 0x98
"""The zone byte a query carries.

`getQueryData` is `getData(bean, 2, 8.0f)` -- it fills the zone field with
UTC+8 and relies on the lock ignoring it under action 2. We send the identical
byte rather than a zero or a "nicer" value, because the only frame this lock is
known to have accepted is the one the app sends, and a query that the firmware
mistook for a set would move the owner's clock.
"""


def encode_zone(hours: float) -> int:
    """`SetTimeZoneCmd.getZone` -- one byte, `10 H S hhhh`.

    Bit 5 is the half-hour flag, bit 4 the sign (1 = UTC+), bits 3-0 the whole
    hours. **Not used to build anything**: the query's zone byte is the
    constant above. It exists so `decode_zone` can be tested against the
    algorithm it inverts rather than against itself.

    Two quirks are faithful to the source: a fractional part of 0.4 or less
    rounds *down* to the hour (Nepal's +5:45 encodes as +5:00), and |hours|
    above 15 truncates to four bits in silence.
    """
    bits = "10"
    magnitude = abs(hours)
    whole = float(int(magnitude))
    bits += "1" if magnitude - whole > 0.4 else "0"
    bits += "1" if hours >= 0.0 else "0"
    binary = bin(int(whole))[2:]
    bits += binary[-4:] if len(binary) >= 4 else binary.rjust(4, "0")
    return int(bits, 2)


def decode_zone(value: int) -> float | None:
    """Read a zone byte back. `None` when bits 7-6 are not `10`.

    The prefix check is the only validation available: every other bit pattern
    is a legal offset, so a byte that is not a zone byte at all decodes to a
    plausible one unless the prefix is tested.
    """
    if value >> 6 != 0b10:
        return None
    hours = float(value & 0x0F)
    if value & 0x20:
        hours += 0.5
    return hours if value & 0x10 else -hours


def decode_zone_reply(value: int) -> float:
    """Read the one-byte payload the 0x33 **query** returns.

    It is not `getZone`'s encoding. The lock keeps its offset in its own
    form: bit 7 set for zero and positive offsets, clear for negative, and
    the low seven bits are the absolute offset in **half-hours**. Settled on
    hardware 2026-09-21 across eight readings at seven distinct offsets --
    `0x80` is UTC, `0x90` is +8, `0x8B` is +5:30, `0x0E` is -7.

    The app has no decoder for this because nothing in it ever sends the
    query; the firmware path exists and the app never exercises it.
    """
    hours = (value & 0x7F) / 2
    return hours if value & 0x80 else -hours


def build_timezone_query(caps: Capabilities, creds: Creds, *,
                         nonce: bytes) -> bytes:
    """0x33 action 2 -- ask the lock which UTC offset it is stamping in.

    **A read, and only a read.** The command's action byte is fixed at
    `ACTION_TZ_QUERY` and this function takes no parameter that could change
    it; `build_timezone_query` is the only builder registered for 0x33, so
    `build(0x33, ...)` cannot reach the setting form either.

    Six fields, in the AES branch's order -- `HexUtils.c("33", mcLen, encMC,
    action, zone, nonce)` (`SetTimeZoneCmd.java:68`). The **non**-AES branch at
    `:60` puts the master code last instead of third; that ordering is almost
    certainly the vendor's bug and it is a branch this integration never takes.

    `nonce` is the 8 bytes from the most recent `0x1E` reply -- the app reads
    the same cached value out of `LockerConfig.B(uuid)`.

    ⚠️ **Whether the lock answers with a value is unknown.** The app's
    `parseCmd` decrypts the reply and then discards it: it never sets `sucess`
    and never reads the returned zone, so no vendor surface displays this and
    there is no oracle. The reply may carry the offset, or the command may be
    write-only with a bare acknowledgement. That is the question this builder
    exists to settle.
    """
    if OP_TIMEZONE not in ALLOW:  # pragma: no cover - structural guard
        raise OpcodeNotAllowed(OP_TIMEZONE)
    fields = _preamble(creds, OP_TIMEZONE)
    fields += [
        ("action", bytes((ACTION_TZ_QUERY,))),
        ("zone", bytes((ZONE_QUERY,))),
        ("nonce", _field(nonce, "nonce")),
    ]
    # Belt and braces: the action byte is a literal three lines up, so this can
    # only fire if somebody edits that constant. It is the difference between
    # reading the owner's timezone and rewriting it.
    if fields[-3][1] != bytes((ACTION_TZ_QUERY,)) or ACTION_TZ_QUERY != 0x02:
        raise FieldError("0x33 may only be built as a query (action 2)")
    return assemble(fields, derive_key(creds.master_code, creds.uuid),
                    caps.encrypt_type(OP_TIMEZONE))


_BUILDERS = {
    OP_STATUS: build_status,
    OP_MOTOR: build_motor,
    OP_MOTOR_LEGACY: build_motor,
    OP_ACCESS_LOG: build_access_log,
    OP_DIAGNOSTICS: build_diagnostics,
    OP_TIMEZONE: build_timezone_query,
}


def build(opcode: int, caps: Capabilities, *args, **kwargs) -> bytes:
    """The only entry point. Checks the allow-list **before** the table.

    Order matters: looking the builder up first would turn a forbidden opcode
    into a KeyError, which reads like a missing feature rather than a refused
    command.

    A motor opcode that disagrees with the model is **refused, not
    substituted**. `build_motor` picks its own opcode from the capability
    table, so asking for 0x22 on a 0x52 model used to return a 0x52 frame
    without saying so -- the allow-list had checked one byte and the wire
    carried another.
    """
    if opcode not in ALLOW:
        raise OpcodeNotAllowed(opcode)
    builder = _BUILDERS[opcode]
    if builder is build_motor and opcode != caps.motor_opcode():
        raise FieldError(
            f"0x{opcode:02X} was requested, but lock type {caps.lock_type} "
            f"({caps.model}) operates its motor with 0x{caps.motor_opcode():02X}. "
            "Refusing rather than silently building a different opcode."
        )
    return builder(caps, *args, **kwargs)
