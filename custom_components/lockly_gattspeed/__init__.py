"""Lockly GATTspeed -- a Lockly lock over Bluetooth, locally."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant

from .const import CONF_HOUSE_CODE, CONF_LOCK_NAME, CONF_LOCK_UUID, CONF_MASTER_CODE
from .link import LocklyError, LocklyLink
from .proto import Creds

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LOCK]

type LocklyConfigEntry = ConfigEntry[LocklyLink]


async def async_setup_entry(hass: HomeAssistant, entry: LocklyConfigEntry) -> bool:
    creds = Creds(
        master_code=entry.data[CONF_MASTER_CODE],
        uuid=bytes.fromhex(entry.data[CONF_LOCK_UUID]),
        house_code=entry.data[CONF_HOUSE_CODE],
    )
    link = LocklyLink(
        hass,
        address=entry.data[CONF_ADDRESS],
        name=entry.data.get(CONF_LOCK_NAME) or entry.title,
        creds=creds,
    )
    entry.runtime_data = link
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    # The first position, read in the background: a lock out of range at
    # startup should not hold up Home Assistant or fail the entry. A command
    # reads the position again anyway.
    entry.async_create_background_task(
        hass, _async_first_read(link), f"lockly_gattspeed first read {link.address}"
    )
    return True


async def _async_first_read(link: LocklyLink) -> None:
    try:
        await link.async_refresh()
    except LocklyError as err:
        _LOGGER.warning("%s: could not read the lock at startup: %s", link.name, err)


async def async_unload_entry(hass: HomeAssistant, entry: LocklyConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.async_stop()
    return unloaded
