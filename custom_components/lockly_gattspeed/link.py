"""The Bluetooth link to one lock: connect, one command, confirm, let go.

A command is always the same four steps, on one connection that is released
afterwards:

1. **connect**, through Home Assistant's own Bluetooth (its adapter, a USB
   dongle or an ESPHome Bluetooth proxy);
2. **`0x1E` status**: the model, the bolt's position, and the nonce the log
   read needs. It moves nothing;
3. **lock or unlock** (`0x52`), sent **once**. It is never repeated after any
   outcome, a timeout included: a timeout means the result is unknown, not
   that nothing happened;
4. **`0x94` log**: the lock's own record of that command says where the bolt
   ended up. A read is safe to repeat, so it is tried a few times.

The credentials never reach a log line, and neither does any frame.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from contextlib import suppress

from bleak.exc import BleakError
from bleak_retry_connector import (
    BLEAK_RETRY_EXCEPTIONS,
    BleakClientWithServiceCache,
    close_stale_connections_by_address,
    establish_connection,
)

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant, callback

from .const import (
    CHUNK,
    CONFIRM_FIRST_READ_DELAY_S,
    CONFIRM_READ_GAP_S,
    CONFIRM_READ_TRIES,
    JAMMED,
    LOCKS_BOLT,
    NOTIFY_UUID,
    READ_TIMEOUT_S,
    REPLY_TIMEOUT_S,
    UNLOCKS_BOLT,
    WRITE_UUID,
)
from .proto import (
    BOOTSTRAP,
    AccessLogPage,
    Capabilities,
    Creds,
    ProtoError,
    ReplyKind,
    UnknownLockType,
    capabilities_for,
    classify,
    derive_key,
    frames,
    parse_access_log_page,
    parse_motor_ack,
    parse_status,
)

_LOGGER = logging.getLogger(__name__)

LOCKING = "locking"
UNLOCKING = "unlocking"

_LINK_ERRORS = (BleakError, TimeoutError, *BLEAK_RETRY_EXCEPTIONS)


class LocklyError(Exception):
    """A command or a read did not succeed. The message is for people."""


class NotReached(LocklyError):
    """The lock could not be reached. Nothing that moves the bolt was sent."""


class CredentialError(LocklyError):
    """The lock refused the stored codes."""


class UnsupportedModel(LocklyError):
    """The lock is a model this integration does not support."""


class CommandRejected(LocklyError):
    """The lock answered and refused the command."""


class OutcomeUnknown(LocklyError):
    """The command was sent and its result could not be read."""


class _Dropped(LocklyError):
    """The connection went away before the lock answered."""


class _Mismatch(LocklyError):
    """A reply that belongs to a different command."""


def bolt_locked(open_type: int) -> bool | None:
    """True or False where a log record's type moves the bolt, else None."""
    if open_type in LOCKS_BOLT:
        return True
    if open_type in UNLOCKS_BOLT:
        return False
    return None


class LocklyLink:
    """One lock. Connected only while it is being read or commanded."""

    def __init__(self, hass: HomeAssistant, address: str, name: str,
                 creds: Creds) -> None:
        self.hass = hass
        self.address = address
        self.name = name
        self._creds = creds
        self.caps: Capabilities | None = None
        self.firmware: str | None = None
        self.locked: bool | None = None
        self.transition: str | None = None
        self.jammed = False
        self._nonce = b""
        self._client: BleakClientWithServiceCache | None = None
        self._connected = False
        self._buf = bytearray()
        self._reply = asyncio.Event()
        self._in_flight = False
        self._busy = asyncio.Lock()
        self._listeners: list[Callable[[], None]] = []

    @property
    def model(self) -> str | None:
        return self.caps.model if self.caps else None

    # ── Listeners ───────────────────────────────────────────────────────────

    @callback
    def register_callback(self, listener: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(listener)

        def remove() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return remove

    @callback
    def _fire(self) -> None:
        for listener in list(self._listeners):
            listener()

    # ── What the rest of the integration calls ─────────────────────────────

    async def async_refresh(self) -> None:
        """Connect, read the model and the bolt's position, let go.

        Used at setup, and by the config flow to prove the codes on the lock
        before anything is saved. Moves nothing.
        """
        async with self._busy:
            try:
                await self._connect()
                await self._read_status_or_not_reached()
            finally:
                await self._disconnect()

    async def async_lock(self) -> None:
        await self._command(lock=True)

    async def async_unlock(self) -> None:
        await self._command(lock=False)

    async def async_stop(self) -> None:
        await self._disconnect()

    # ── The command ─────────────────────────────────────────────────────────

    async def _command(self, *, lock: bool) -> None:
        async with self._busy:
            try:
                await self._connect()
                await self._read_status_or_not_reached()
                event_id = await self._send_once(lock=lock)
                await self._confirm(lock=lock, event_id=event_id)
            finally:
                if self.transition is not None:
                    # Nothing may leave the entity showing Locking... for good.
                    self.transition = None
                    self._fire()
                await self._disconnect()

    async def _send_once(self, *, lock: bool) -> int:
        """Operate the bolt. **Exactly once, whatever happens.**

        No `except` here sends again, and none ever may: re-sending after a
        timeout could lock a door someone is standing in, or unlock one they
        believe is shut. Returns the event id the lock gave this command.
        """
        caps = self.caps
        if caps is None:  # pragma: no cover - the status read sets it or raises
            raise UnsupportedModel("the lock model is unknown")
        frame = frames.build(caps.motor_opcode(), caps, self._creds,
                             lock=lock, access_code=self._creds.house_code)
        self.transition = LOCKING if lock else UNLOCKING
        self.jammed = False
        self._fire()
        _LOGGER.debug("%s: %s sent", self.name, "lock" if lock else "unlock")
        try:
            raw = await self._exchange(frame, REPLY_TIMEOUT_S)
            ack = parse_motor_ack(self._classify(raw, caps.motor_opcode()).plain)
        except (_Dropped, _Mismatch, ProtoError, *_LINK_ERRORS) as err:
            # The frame may have reached the lock, so the position is unknown.
            self.locked = None
            _LOGGER.warning("%s: no readable answer to the %s command (%s); it "
                            "was not repeated", self.name,
                            "lock" if lock else "unlock", type(err).__name__)
            raise OutcomeUnknown(
                "The lock did not answer. The command was not repeated, and "
                "whether the bolt moved is unknown."
            ) from err
        if ack.rejected:
            raise CommandRejected("The lock refused the command.")
        if not ack.accepted:
            raise LocklyError(
                f"The lock did not carry out the command "
                f"({ack.to_log()['result_name']})."
            )
        # Accepted. Show the commanded position until the lock's own log says
        # where the bolt went. An acknowledgement carries no bolt position.
        self.locked = lock
        self.transition = None
        self._fire()
        _LOGGER.debug("%s: acknowledged", self.name)
        return ack.event_id

    async def _confirm(self, *, lock: bool, event_id: int) -> None:
        """Find this command's record in the lock's log. Reads only."""
        await asyncio.sleep(CONFIRM_FIRST_READ_DELAY_S)
        for attempt in range(1, CONFIRM_READ_TRIES + 1):
            try:
                if not self._connected:
                    await self._connect()
                page = await self._read_log()
            except (LocklyError, ProtoError, *_LINK_ERRORS) as err:
                _LOGGER.debug("%s: log read %d failed (%s)", self.name, attempt,
                              type(err).__name__)
            else:
                if self._apply_log(page, event_id):
                    _LOGGER.debug("%s: confirmed on read %d", self.name, attempt)
                    return
            if attempt < CONFIRM_READ_TRIES:
                await asyncio.sleep(CONFIRM_READ_GAP_S)
        _LOGGER.warning("%s: the lock accepted the %s command, but its log did "
                        "not show it after %d reads", self.name,
                        "lock" if lock else "unlock", CONFIRM_READ_TRIES)

    @callback
    def _apply_log(self, page: AccessLogPage, event_id: int) -> bool:
        """Set the bolt from the log. False if this command is not in it yet."""
        types = {record.event_id: record.open_type for record in page.records}
        if event_id not in types:
            return False
        if types[event_id] in JAMMED:
            self.jammed = True
            self.locked = None
            self._fire()
            return True
        # The newest record that moves the bolt: ours, or someone's after it.
        moves = sorted(i for i, t in types.items()
                       if i >= event_id and bolt_locked(t) is not None)
        if moves:
            self.locked = bolt_locked(types[moves[-1]])
        # Otherwise the record moves no bolt, and the commanded position stands.
        self._fire()
        return True

    # ── Reads ───────────────────────────────────────────────────────────────

    async def _read_status_or_not_reached(self) -> None:
        try:
            await self._read_status()
        except (_Dropped, _Mismatch, ProtoError, *_LINK_ERRORS) as err:
            raise NotReached(
                f"Could not read {self.name}'s status. Nothing was sent."
            ) from err

    async def _read_status(self) -> None:
        # BOOTSTRAP until the status reply names the model; it can build a
        # status read and nothing else.
        caps = self.caps or BOOTSTRAP
        raw = await self._exchange(frames.build(frames.OP_STATUS, caps, self._creds),
                                   REPLY_TIMEOUT_S)
        status = parse_status(self._classify(raw, frames.OP_STATUS).plain)
        if self.caps is None or self.caps.lock_type != status.lock_type:
            try:
                self.caps = capabilities_for(status.lock_type)
            except UnknownLockType as err:
                raise UnsupportedModel(str(err)) from err
        self._nonce = status.nonce
        self.firmware = status.firmware
        self.locked = status.locked
        self.jammed = False
        self._fire()

    async def _read_log(self) -> AccessLogPage:
        """The newest page of the lock's own log."""
        caps = self.caps
        if caps is None:  # pragma: no cover - the status read sets it or raises
            raise UnsupportedModel("the lock model is unknown")
        raw = await self._exchange(
            frames.build(frames.OP_ACCESS_LOG, caps, self._creds,
                         nonce=self._nonce, cursor=1),
            READ_TIMEOUT_S)
        return parse_access_log_page(self._classify(raw, frames.OP_ACCESS_LOG).plain)

    # ── The radio ───────────────────────────────────────────────────────────

    def _ble_device(self):
        return bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True)

    async def _connect(self) -> None:
        if self._client is not None:
            # A connection that dropped: release it before taking a new one.
            await self._disconnect()
        device = self._ble_device()
        if device is None:
            raise NotReached(
                f"{self.name} is not in range of any Bluetooth radio Home "
                "Assistant can connect with. Nothing was sent."
            )
        await close_stale_connections_by_address(self.address)
        try:
            client = await establish_connection(
                BleakClientWithServiceCache,
                device,
                self.name,
                self._disconnected,
                ble_device_callback=lambda: self._ble_device() or device,
                use_services_cache=True,
            )
        except _LINK_ERRORS as err:
            raise NotReached(
                f"Could not connect to {self.name}. Nothing was sent."
            ) from err
        try:
            # The lock drops a connection that has not been written to for
            # about ten seconds. Write first, so a slow subscribe cannot run
            # the clock out. The lock ignores these four bytes.
            await client.write_gatt_char(WRITE_UUID, bytes(4), response=False)
            await client.start_notify(NOTIFY_UUID, self._notification)
        except _LINK_ERRORS as err:
            with suppress(*_LINK_ERRORS):
                await client.disconnect()
            raise NotReached(
                f"Connected to {self.name} but could not subscribe. Nothing was sent."
            ) from err
        self._client = client
        self._connected = True
        _LOGGER.debug("%s: connected", self.name)

    async def _disconnect(self) -> None:
        client, self._client = self._client, None
        self._connected = False
        if client is not None:
            with suppress(*_LINK_ERRORS):
                await client.disconnect()
            _LOGGER.debug("%s: released", self.name)

    @callback
    def _disconnected(self, _client: BleakClientWithServiceCache) -> None:
        self._connected = False
        # Wake a waiting exchange at once rather than at its timeout.
        self._reply.set()

    @callback
    def _notification(self, _char, data: bytearray) -> None:
        """Reassemble on the reply's own length field, never on a pause."""
        if not self._in_flight:
            # No correlation id in this protocol: a stray notification must not
            # be taken for the next command's answer.
            return
        self._buf.extend(data)
        if len(self._buf) >= 6 and len(self._buf) >= int.from_bytes(self._buf[4:6], "little"):
            self._reply.set()

    async def _exchange(self, frame: bytes, timeout: float) -> bytes:
        """Write one frame and wait for one reply."""
        client = self._client
        if client is None or not self._connected:
            raise _Dropped("not connected")
        self._buf.clear()
        self._reply.clear()
        self._in_flight = True
        try:
            for i in range(0, len(frame), CHUNK):
                await client.write_gatt_char(WRITE_UUID, frame[i:i + CHUNK],
                                             response=True)
            async with asyncio.timeout(timeout):
                await self._reply.wait()
            if not self._connected:
                raise _Dropped("the connection dropped before the lock answered")
            return bytes(self._buf)
        finally:
            self._in_flight = False

    def _classify(self, raw: bytes, expect: int):
        caps = self.caps or BOOTSTRAP
        reply = classify(raw, expect,
                         derive_key(self._creds.master_code, self._creds.uuid),
                         aes_f0=caps.aes_encrypt_f0, code_len=caps.reply_code_len())
        if reply.kind is ReplyKind.ERROR:
            if reply.credential_failure:
                raise CredentialError(
                    "The lock refused the stored codes. If its master code was "
                    "changed, remove the lock from Home Assistant and add it again."
                )
            raise LocklyError(f"The lock answered with an error: {reply.message}")
        if reply.kind is ReplyKind.MISMATCH:
            raise _Mismatch(f"a reply for 0x{reply.opcode:02X}, not 0x{expect:02X}")
        return reply
