"""The lock entity -- the only entity this integration creates."""

from __future__ import annotations

from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import LocklyConfigEntry
from .const import DOMAIN
from .link import LOCKING, UNLOCKING, LocklyError, LocklyLink


async def async_setup_entry(
    hass: HomeAssistant,
    entry: LocklyConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([LocklyLock(entry.runtime_data)])


class LocklyLock(LockEntity):
    """The bolt.

    Its position comes from the lock: the status read at the start of every
    connection, and the lock's own log record of each command. Between
    commands nothing is read, so a change made at the lock (keypad,
    fingerprint, key, the Lockly app, the lock's own auto-lock) shows at the
    next command, or after a reload.
    """

    _attr_has_entity_name = True
    _attr_name = None
    _attr_should_poll = False

    def __init__(self, link: LocklyLink) -> None:
        self._link = link
        self._attr_unique_id = link.address

    @property
    def device_info(self) -> DeviceInfo:
        """Built on each read, so the model and firmware fill in once known."""
        return DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, self._link.address)},
            identifiers={(DOMAIN, self._link.address)},
            manufacturer="Lockly",
            name=self._link.name,
            model=self._link.model,
            sw_version=self._link.firmware,
        )

    @property
    def is_locked(self) -> bool | None:
        return self._link.locked

    @property
    def is_locking(self) -> bool:
        return self._link.transition == LOCKING

    @property
    def is_unlocking(self) -> bool:
        return self._link.transition == UNLOCKING

    @property
    def is_jammed(self) -> bool:
        return self._link.jammed

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self._link.register_callback(self._handle_update))

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()

    async def async_lock(self, **kwargs: Any) -> None:
        try:
            await self._link.async_lock()
        except LocklyError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_unlock(self, **kwargs: Any) -> None:
        try:
            await self._link.async_unlock()
        except LocklyError as err:
            raise HomeAssistantError(str(err)) from err
