"""Access-log page decoding -- the `0x94` reply.

**The log is not a push channel.** Nothing here arrives unsolicited; every
record has to be asked for. The lock has been measured silent across 4,349 s
of held link with the notify characteristic subscribed throughout, and the
application has no code path to receive a push either -- the vendor's own app
shows no update for a physical unlock until you pull to refresh.

Two layouts exist and they are the same length. `0x7C` (`Log124Cmd`) spends
bytes 7..10 on a single 4-byte `pwdId`; `0x94` (`Log148Cmd`) splits the same
four bytes into `pwdId` and `relationUserId`. **Feeding one parser the other's
page produces plausible records with a wrong id on every row** -- no length
mismatch, no CRC failure, no exception. This module decodes `0x94` only, which
is the layout for every lock whose `isSupport148Cmd()` is true, and `0x7C` is
kept out of the allow-list rather than guessed at.

Everything is little-endian and everything is **unsigned**. The application
reads four of these fields as signed shorts and renders negative ids that match
nothing; `relationUserId` and `pwdId` sit two bytes apart and are read with two
different helpers with two different sign behaviours. That is a vendor defect,
not a protocol fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import ProtoError

HEADER_LEN = 6
RECORD_LEN = 13


class AccessLogError(ProtoError, ValueError):
    """A page could not be decoded.

    Raised rather than swallowed, on purpose. `PagingLogCmd.parseCmd` returns
    early on a malformed reply without setting its success flag and without
    clearing the record list, so a caller checking only `isSucess()` treats a
    truncated page as a successful empty one -- and may re-read the *previous*
    page's records. Silence is the bug; this is the fix.
    """


# The event taxonomy. Generated from `UnlockRecordAdapter.M0`'s two-stage
# switch, which handles 110 distinct values spanning 2..117 -- the
# `MessageManage` constant table stops at 36 and is a trap: keying a parser on
# it silently drops door-jam, tamper, low-battery, auto-lock-fired, door-ajar
# and every lock-direction event, which is the exact set a home-automation
# integration most wants.
#
# Names are ours, derived from the vendor's resource identifiers. They are
# stable keys, not translations -- never render one to a user.
#
# ⚠️ **A resource identifier is not the string it displays, and here they
# disagree about direction again and again.** `unlock_touch_screen` displays
# "Touchscreen Locking"; `unlock_by_app` displays "Locked by App";
# `log_event_type_lock_image` displays "Unlocked via Visage ID";
# `log_event_type_lock_homekey` displays "Unlocked via Apple home key". The id
# is what the string was once called; the text is what the vendor means now.
#
# **The text is available to us.** `strings.xml` is absent from the `--no-res`
# source tree but present in the separately decoded resource bundle, which is
# why this comment used to claim there was no `strings.xml` to check against.
# There is. Check a name against it before trusting the identifier.
OPEN_TYPES: dict[int, str] = {
    # ── Corrected on hardware, 2026-09-21 ────────────────────────────────
    # The renderer table starts at 2, so 1 was missing entirely -- and it is
    # the single most common value in this lock's log (22 of 50 records).
    # Identified by correlating three of our own motor commands against their
    # ACK `event_id`: 4544 unlock -> ot 1, 4545 **lock** -> ot 43, 4546
    # unlock -> ot 1, timestamps matching to the second.
    #
    # ⚠️ 43's vendor resource id is `unlock_by_app`, and on this hardware it
    # accompanied a LOCK. The pairing corroborates it: 1 and 43 each occur 22
    # times, always 1 then 43. Named for what the lock does, not for what the
    # string says; raised with `windows` rather than silently reconciled.
    #
    # ── Corrected against the vendor's own app, 2026-09-21 ────────────────
    # Four screenshots of the app's History screen were joined to this lock's
    # `0x94` ring by timestamp: 40 rows matched 40 records, `event_id`
    # 4524..4563 contiguous, no gaps and no duplicates, under a single
    # one-hour shift. That makes the app's rendered text an oracle for what
    # the vendor *means* by each value -- a stronger one than the resource
    # identifier, which is only what the vendor once named it.
    #
    # It confirmed 43 independently ("Locked by App", 12/12) and corrected
    # two more, both **backwards about direction**, which is the one thing a
    # consumer of this taxonomy cannot recover for itself: 41 and 92 below.
    # Nothing here derives lock/unlock from the number, so the name is the
    # only signal, and two of the nine types this lock actually emits had it
    # inverted.
    1: "unlock_by_app",
    2: "keyboard_unlock",
    3: "temp_pwd_unlock",
    4: "key_unlock",  # app renders "Unlocked Manually" -- may be wider
    5: "family_member_unlock",
    6: "update_lock_clock",
    7: "lock_alarm",
    8: "low_power_warning",
    9: "emergency_pwd",
    10: "rfid_unlock",
    11: "fingerprint_unlock",
    12: "unlock_one_time_password",
    13: "guest_key_unlock",
    # App: "Unlocked by Family User LOCKLY Touch Screen" -- the family-user
    # counterpart of 2, not a physical key. Renamed off the resource id
    # because "key" already means the *manual* opening in 4 `key_unlock`,
    # which the app renders "Unlocked Manually".
    14: "family_keyboard_unlock",
    15: "unlock_omk_guest_password",
    16: "unlock_omk_guest_password",
    17: "unlock_omk_onece_password",
    18: "unlock_oac_guest",
    20: "unlock_oac_one_time",
    21: "unlock_one_time_password",
    22: "lt_guest_bt_pw_unlock",
    23: "lt_guest_bt_pw_unlock",
    24: "lt_guest_pw_unlock",
    25: "lt_app_unlock",
    26: "lt_guest_bt_unlock",
    27: "lt_family_bt_unlock",
    28: "unlock_oac_guest",
    29: "unlock_oac_one_time",
    30: "lt_guest_omk_unlock",
    31: "lt_guest_omk_once_unlock",
    32: "fingerprint_unlock_alt",
    33: "rfid_unlock_alt",
    36: "zwave_unlock",
    # 37-39 are dispatched separately from the block above
    # (`UnlockRecordAdapter.java:519-533` -> `:1178-1191`) and are absent from
    # every constant table. They complete the 37-40 fault/tamper block.
    37: "door_jammed",
    38: "door_jammed_sensor",
    39: "cover_open",
    40: "cover_close",
    41: "lock_touch_screen",  # resource says unlock; app+hardware say lock
    # strings.xml: `unlock_auto_mode` displays **"Auto lock"**. Corroborated
    # on hardware: 4506 unlocked at 16:05:13 and 4507 fired 42 at 16:10:15,
    # five minutes later -- an auto-lock, not a second opening.
    42: "lock_auto_mode",
    43: "lock_by_app",  # vendor resource says unlock; hardware says lock
    44: "closedoor_by_touch_pgkey",
    45: "event_stream_117",
    46: "event_stream_118",
    47: "lock_by_lockly",
    48: "lock_by_up_handle",
    49: "lock_by_down_handle",
    50: "unlock_by_down_handle",
    51: "enter_welcome_mode",
    52: "exit_welcome_mode",
    53: "multiple_open_door",
    54: "employee_app_open_door",
    55: "employee_password_open_door",
    56: "unlock_finger_print",
    57: "unlock_rfid",
    58: "zwave_lock",
    59: "check_lock",
    60: "rf_unlock",
    61: "wireless_doorbell_unlock",
    62: "door_no_close",
    63: "ebadge_open",
    64: "ebadge_close",
    65: "multiple_open_door",
    66: "multiple_open_door",
    67: "fingerprint_unlock_alt2",
    68: "rfid_unlock_alt2",
    69: "offline_rfid_unlock",
    70: "offline_rfid_unlock_alt",
    71: "violence",
    72: "power_on",
    73: "emergency",
    74: "multiple_user_open_door",
    75: "multiple_user_open_door",
    76: "safe_power_off",
    77: "emergency_fp",
    78: "in_security_mode",
    79: "out_security_mode",
    80: "close_manual",
    81: "close_auto",
    82: "open_close_door",
    83: "open_door_by_key",
    84: "press_doorbell",
    85: "manget_door_error",
    86: "route_connect_fail",
    87: "route_connect_ok",
    88: "mqtt_connect_fail",
    89: "mqtt_connect_ok",
    90: "not_find_route",
    91: "null_pack",
    92: "unlock_face",  # resource `lock_image`; app "Unlocked via Visage ID"
    # ⚠️ Swapped against their resource ids, which is the vendor pattern.
    # `log_event_type_lock_homekey` displays "Unlocked via Apple home key"
    # and `log_event_type_unlock_homekey` displays "Locked via Apple home
    # key". No hardware here -- the strings are the authority.
    93: "unlock_homekey",
    94: "lock_homekey",
    95: "route_disconnect",
    96: "server_disconnect",
    97: "lock_error",
    98: "exit_welmode_error",
    99: "home_key_password_unlock",
    100: "password_lock",
    101: "home_key_password_lock",
    102: "face_recognition_failed",
    103: "radar_fail",
    104: "radar_fail_day",
    105: "unlock_virtual_keypad",
    106: "unlock_home_nfc",
    107: "lock_home_nfc",
    108: "unlock_people_touch_fp",
    109: "oac_activation",
    110: "lock_door_open",
    111: "portal_unlock",
    112: "portal_lock",
    113: "google_unlock",
    114: "google_lock",
    115: "alexa_unlock",
    116: "alexa_lock",
    117: "door_sensor_close",
}

JAM_EVENTS = frozenset({37, 38})
"""The bolt ran and did not complete. 37 is motor stall; 38 is the same
conclusion reached via the door sensor. Both hide the user row in the app's own
UI because there is no user for them, and both carry a `pwd_id` sentinel."""

TAMPER_EVENTS = frozenset({39})
"""The battery/tamper cover was opened. 37-40 is one contiguous fault block."""

NO_ACTOR = frozenset(JAM_EVENTS | TAMPER_EVENTS | {6, 7, 8, 40, 62, 72, 76, 81})
"""Events with no operator: clock set, alarm, low battery, cover close, door
left ajar, power on, safe power off, auto-lock fired. `pwd_id` on these is not
a credential id and must not be resolved as one.

⚠️ **Incomplete against hardware, and known to be.** This lock files 4
(manual open), 41 (touchscreen lock), 42 (auto-lock) and 80 (manual close)
with `PWD_ID_NONE` in every one of 15 observations, and none of the four is
listed here. The set is what the application declares; the sentinel is what
the lock sends. Do not use this set alone to decide whether there is an
operator -- `has_actor` checks the value too, which is why it is right and
this set is merely useful."""

PWD_ID_NONE = 0xFFFF
"""All-ones u16: "no operator". Observed on every 4/41/42/80 record.

Not the only sentinel-shaped value in the field. **`pwd_id == 0` is not
understood** -- see `has_actor`."""


def event_name(open_type: int) -> str:
    """A stable key for an `openType`, named where we know it.

    **Never resolves to a default.** The app's renderer falls through to "app
    unlock" for anything it does not recognise, which turns an unknown event
    into a confident wrong answer; the range is known to be open, so an
    unmapped value is reported as itself.
    """
    return OPEN_TYPES.get(open_type, f"unknown_{open_type}")


@dataclass(frozen=True)
class AccessLogRecord:
    """One 13-byte log entry."""

    open_type: int
    pwd_id: int
    relation_user_id: int
    event_id: int
    """The lock's own event counter. The application calls this `lockId`; the
    vendor's *cloud* API calls the same field `eventId`, which is the accurate
    name and the one used here. It is the correct dedup key -- but see the
    module note in the plan: whether it shares endianness with the motor ACK's
    counter is unresolved, so do not correlate the two without measuring."""

    when: datetime | None
    """`None` when the six timestamp bytes are not a real date.

    Not an error. A lock that has lost power reports dates decades off, and the
    vendor's own embedded capture contains a cluster of them. The record is
    still a real event, so it is kept and the raw fields are preserved.

    ⚠️ **Never order by this, and never take the maximum of it to find the
    latest event. Order by `event_id`.** Observed on hardware 2026-09-21: a
    single 50-record page held `event_id` 4567 stamped 23:08:38 followed
    immediately by 4568 stamped **22:35:49** -- time running backwards while
    the counter ran forwards, because the timestamp frame moved by an hour
    between the two. Bound to real time through the motor ACK's `event_id`,
    4567 was accurate to 3 s and 4571 was 3,603 s early.

    It is not a clock fault: the status reply's `lock_clock` read correct to
    within a second nine seconds after 4571 was written, so the log's stamp
    and the lock's clock are **not the same time source** and can disagree by
    a whole hour. Treat this field as the lock's opinion of when, not as an
    ordering key.

    **Naive because the bytes are naive** -- the record carries six values and
    no zone, so this field reports exactly that and nothing more. It is not
    the value to publish: use `when_utc()`, which is explicit about the offset
    it applies.

    The lock holds a fixed **offset**, not a zone. The cloud record carries
    `tz` "-7:00" beside `tzId` "America/Los_Angeles", and it is the offset the
    lock is given -- which is how the stamping frame moved to -8:00 while the
    zone was still on -7:00, something a zone-aware clock could not do. So the
    offset is an input a caller must supply, not a property this module can
    infer."""

    raw_when: tuple[int, int, int, int, int, int]
    """`(yy, mm, dd, hh, mm, ss)` exactly as received, always populated."""

    @property
    def name(self) -> str:
        return event_name(self.open_type)

    def when_utc(self, offset_minutes: int) -> datetime | None:
        """`when` as an aware UTC instant, given the lock's offset.

        **This is the value to publish.** Home Assistant renders an aware
        datetime in each viewer's own timezone; a naive one it cannot place at
        all, and a local-looking string forces every consumer to guess.

        `offset_minutes` is the lock's, not the viewer's -- the two differ the
        moment somebody opens the dashboard from another country. The
        authoritative source is the cloud record's `tz` field (`"-7:00"`), read
        once at setup alongside the credentials.

        ⚠️ **A wrong offset produces a confident wrong instant**, and the
        lock's frame has been observed to move by an hour mid-ring
        (2026-09-21). Keep the naive `when` and the offset used beside any
        stored conversion so a later correction can recompute rather than
        guess; that is what the bench activity record does.
        """
        if self.when is None:
            return None
        return (self.when - timedelta(minutes=offset_minutes)).replace(
            tzinfo=timezone.utc)

    @property
    def has_actor(self) -> bool:
        """Whether `pwd_id` is meaningful as a credential reference.

        `pwd_id` is three namespaces wearing one coat -- a credential id, a
        fingerprint/RFID sensor id, or a sentinel -- and which one depends on
        `open_type`. The vendor app gets this wrong via an unsatisfiable guard
        (`a == "11" && a == "10" && a == "1"`) and looks sensor ids up in the
        credential table, where they collide with real users.

        **Both tests, because either alone is wrong on this hardware.**
        `NO_ACTOR` misses four open types the lock actually sends the sentinel
        for, so the set alone would hand `0xFFFF` to a credential lookup --
        the same class of mistake as the vendor's, reached from the other
        side.

        ⚠️ **True here does not mean the id resolves to a person yet.**
        `pwdId == 0` is the **master code** -- `QueryPwdCmd.getMyLockerPwd`
        returns the record whose id is 0, and `getAccessCode` skips that
        record when listing access codes, so the host is deliberately not a
        guest. Guest ids start at 1 (the vendor's own embedded vector has
        host 0 and ten guests in 1..16), and this lock's `pwdId` is one byte:
        `isSupportPwdId2Bytes()` is false for type 105.

        **It is the user id. Settled 2026-09-21 against the cloud's own
        credential registry**, which the account's device record carries as
        `usrarr` and which lists every enrolled credential with its own
        per-type index:

            fingerprints  index 1,2,3 = owner   index 4,5 = the family user
            faces         index 1     = owner   index 2   = the family user
            access codes  index 1     = the family user (the owner's is the
                                        master code and is not listed)

        **None of those indices is what the log reports.** The owner's
        fingerprint unlock logged `pwd_id` 0 while their fingers are 1, 2, 3;
        their face unlock logged 0 while their face is 1; the family user's
        keypad unlock logged 2 while their access code is index 1. Every one
        of the three namespaces disagrees with the log, and the *user* id
        agrees with all three -- owner 0, family user 2.

        So the "three namespaces wearing one coat" warning belongs to the
        **credential-query** command's `pwdId`, not to this field. Here the
        number is the person's slot whatever they touched.

        The id space is **partitioned by role, not densely allocated**: 0
        Owner, 1 Sub Admin, 2+ Family/Guest, 52 total. The cloud record's
        `secondAdm` reads `N` on this lock, which is why nothing has ever
        logged 1.

        **The lock does not know who anyone is.** It stores indices and
        nothing else; every name in the vendor's UI comes from the app
        matching those indices against its own account data. So the open
        question is not "is this a person or a credential" -- it is *which
        table a consumer would have to join against*, and the answer is never
        "none". A record can be attributed only by something outside the lock.

        ⚠️ **Which makes slot reuse a real hazard for attribution.** Delete a
        user and add another into the same slot and every historical record
        carrying that index silently re-attributes to the new occupant. The
        lock has no way to notice; the index was never a person. Anything
        built on this -- `changed_by` above all -- has to decide whether it is
        naming who acted *then* or who holds the slot *now*, and those stop
        agreeing the first time a credential is recycled.

        Either way `pwd_id` does not name a person without a table this
        integration does not fetch.

        `relation_user_id` was 0 in all 66 records, so it settles nothing --
        and since every id on a 52-user lock fits in one byte, the upper half
        stays zero and the `0x94`/`0x7C` split stays unfalsifiable through
        normal use. A consumer that resolves `pwd_id` to a person needs the
        user-versus-credential question answered first; this property only
        rules out the case where there is provably nobody.
        """
        return self.pwd_id != PWD_ID_NONE and self.open_type not in NO_ACTOR

    def to_log(self) -> dict[str, object]:
        """Decoded fields only -- there is nothing secret in a log record, but
        the shape matches the project's other `to_log` helpers.

        ⚠️ The name key is `event_name`, **not** `event`. Every logger in this
        project writes the record type under `event`, so a dict with its own
        `event` key cannot be splatted into one -- it raises
        `TypeError: got multiple values for argument 'event'`. That is exactly
        what happened on the first live read, which decoded 50 records
        correctly and then threw while writing the first of them.
        """
        return {
            "open_type": self.open_type,
            "event_name": self.name,
            "pwd_id": self.pwd_id,
            "relation_user_id": self.relation_user_id,
            "event_id": self.event_id,
            "when": self.when.isoformat() if self.when else None,
            "when_valid": self.when is not None,
            # The six timestamp bytes as received. Not redundant with `when`:
            # a record whose date will not parse reports `when: null`, and
            # without this the reading is gone -- which is the one case where
            # anybody would want to see it. The field carries a timestamp and
            # nothing else; there is no key material in it and nothing
            # replayable.
            "raw_when": list(self.raw_when),
        }


@dataclass(frozen=True)
class AccessLogPage:
    """One page, plus the cursor arithmetic for the next request."""

    total: int
    """Records matching the requested window, across all pages."""

    delivered: int
    """Cumulative count **including this page** -- the app's `curSum`."""

    count: int
    """Records the header claims are in this page."""

    records: tuple[AccessLogRecord, ...]

    @property
    def is_end(self) -> bool:
        """`>=`, not `==`.

        A lock reporting more delivered than total terminates the read rather
        than looping forever, and a zero-record reply ends immediately because
        `0 >= 0`."""
        return self.delivered >= self.total

    @property
    def next_cursor(self) -> int:
        """`curSum + 1` -- a 1-based ordinal into the matching set.

        Not `cursor + 1`, and not a page number. Getting this wrong re-reads
        the first record of the page just delivered, forever."""
        return self.delivered + 1

    def to_log(self) -> dict[str, object]:
        return {
            "total": self.total,
            "delivered": self.delivered,
            "count": self.count,
            "records": len(self.records),
            "is_end": self.is_end,
        }


def parse_access_log_page(plain: bytes) -> AccessLogPage:
    """Decode one decrypted, padding-stripped `0x94` body.

    `plain` is what `classify()` returns as `Reply.plain` -- the frame header
    and CRC are already gone.
    """
    if len(plain) < HEADER_LEN:
        raise AccessLogError(
            f"access-log page is {len(plain)} bytes; the header alone is "
            f"{HEADER_LEN}. A lock with no matching records still returns a "
            "full header, so this is a truncated reply, not an empty result."
        )

    total = int.from_bytes(plain[0:2], "little")
    delivered = int.from_bytes(plain[2:4], "little")
    count = int.from_bytes(plain[4:6], "little")

    body = plain[HEADER_LEN:]
    available = len(body) // RECORD_LEN
    if count > available:
        # The app tolerates this silently via a `length() >= 26` loop guard.
        # Say so instead: a short page means records were lost, and a caller
        # advancing its cursor by `delivered` would skip them.
        raise AccessLogError(
            f"header claims {count} records but the body holds {available} "
            f"({len(body)} bytes). Refusing to advance the cursor past records "
            "that were not delivered."
        )

    records = tuple(
        _record(body[i * RECORD_LEN:(i + 1) * RECORD_LEN]) for i in range(count)
    )
    return AccessLogPage(total=total, delivered=delivered, count=count,
                         records=records)


def _record(raw: bytes) -> AccessLogRecord:
    yy, mm, dd, hh, mi, ss = raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]
    try:
        # Plain binary, not BCD: year 22 travels as 0x16, second 59 as 0x3B.
        # A BCD reading decodes 2026 as 2032 and 13:00 as 19:00.
        when = datetime(2000 + yy, mm, dd, hh, mi, ss)
    except ValueError:
        when = None
    return AccessLogRecord(
        open_type=raw[6],
        pwd_id=int.from_bytes(raw[7:9], "little"),
        relation_user_id=int.from_bytes(raw[9:11], "little"),
        event_id=int.from_bytes(raw[11:13], "little"),
        when=when,
        raw_when=(yy, mm, dd, hh, mi, ss),
    )
