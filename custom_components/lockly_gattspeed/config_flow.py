"""Set up a lock: find it, sign in to Lockly once, prove the codes on the lock.

The sign-in fetches the lock's three codes from the Lockly account and is then
forgotten. The email, the password, its hash and the token are never saved;
the entry keeps the lock's address, its name and the three codes, and only
after the lock itself has accepted them.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS, CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .cloud import (
    CloudAuthError,
    CloudError,
    CloudLock,
    async_fetch_account,
    sha256_hex,
)
from .const import (
    CONF_HOUSE_CODE,
    CONF_LOCK_NAME,
    CONF_LOCK_UUID,
    CONF_MASTER_CODE,
    DOMAIN,
    LOCAL_NAME_PREFIXES,
)
from .link import CredentialError, LocklyError, LocklyLink, UnsupportedModel
from .proto import Creds
from .proto.crypto import check_master_code

_LOGGER = logging.getLogger(__name__)

CONF_LOCK = "lock"

MIN_UUID_BYTES = 12
"""The key derivation reads the first twelve bytes of the lock uuid."""


def _is_lockly(info: BluetoothServiceInfoBleak) -> bool:
    return bool(info.name) and info.name.upper().startswith(LOCAL_NAME_PREFIXES)


def creds_from(lock: CloudLock) -> Creds | None:
    """The three codes as the Bluetooth frames need them, or None if unusable."""
    try:
        check_master_code(lock.master_code)
        uuid = bytes.fromhex(lock.uuid_hex)
    except ValueError:
        return None
    if len(uuid) < MIN_UUID_BYTES or not lock.house_code.isdigit():
        return None
    return Creds(master_code=lock.master_code, uuid=uuid, house_code=lock.house_code)


class LocklyGattspeedConfigFlow(ConfigFlow, domain=DOMAIN):
    """Bluetooth discovery or a pick from what is in range, then the sign-in."""

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._ble_name: str | None = None
        self._discovered: dict[str, str] = {}
        self._locks: list[CloudLock] = []

    @property
    def _shown_name(self) -> str:
        return self._ble_name or self._address or "Lockly"

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._address = discovery_info.address
        self._ble_name = discovery_info.name
        self.context["title_placeholders"] = {"name": self._shown_name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return await self.async_step_cloud()
        self._set_confirm_only()
        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={"name": self._shown_name},
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            self._address = user_input[CONF_ADDRESS]
            self._ble_name = self._discovered.get(self._address)
            await self.async_set_unique_id(self._address, raise_on_progress=False)
            self._abort_if_unique_id_configured()
            return await self.async_step_cloud()

        configured = self._async_current_ids()
        found = [
            info
            for info in async_discovered_service_info(self.hass, connectable=True)
            if _is_lockly(info) and info.address not in configured
        ]
        if not found:
            return self.async_abort(reason="no_devices_found")
        self._discovered = {info.address: info.name for info in found}
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): vol.In(
                        {
                            info.address: f"{info.name} ({info.address})"
                            for info in sorted(found, key=lambda i: i.rssi, reverse=True)
                        }
                    )
                }
            ),
        )

    async def async_step_cloud(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Sign in once. Nothing typed here is kept."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                locks = await async_fetch_account(
                    async_get_clientsession(self.hass),
                    user_input[CONF_EMAIL].strip(),
                    sha256_hex(user_input[CONF_PASSWORD]),
                )
            except CloudAuthError:
                errors["base"] = "cloud_auth"
            except (CloudError, TimeoutError, OSError) as err:
                _LOGGER.debug("Lockly sign-in failed: %s", type(err).__name__)
                errors["base"] = "cloud_unreachable"
            else:
                if not locks:
                    errors["base"] = "cloud_no_locks"
                else:
                    self._locks = locks
                    if len(locks) == 1:
                        return await self._async_try_lock(locks[0])
                    return await self.async_step_pick_lock()

        return self._show_cloud(errors)

    def _show_cloud(self, errors: dict[str, str]) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="cloud",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.EMAIL,
                                           autocomplete="username")
                    ),
                    vol.Required(CONF_PASSWORD): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.PASSWORD,
                                           autocomplete="current-password")
                    ),
                }
            ),
            errors=errors,
            description_placeholders={"name": self._shown_name},
        )

    async def async_step_pick_lock(
        self, user_input: dict[str, Any] | None = None, errors: dict[str, str] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return await self._async_try_lock(self._locks[int(user_input[CONF_LOCK])])
        return self.async_show_form(
            step_id="pick_lock",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_LOCK): vol.In(
                        {
                            str(i): lock.name or lock.ble_name or f"Lock {i + 1}"
                            for i, lock in enumerate(self._locks)
                        }
                    )
                }
            ),
            errors=errors or {},
            description_placeholders={"name": self._shown_name},
        )

    async def _async_try_lock(self, lock: CloudLock) -> ConfigFlowResult:
        """Prove the codes on the lock itself, then save them. Moves nothing."""
        assert self._address is not None
        creds = creds_from(lock)
        if creds is None:
            return await self._async_failed("cloud_bad_record")
        name = lock.name or self._ble_name or "Lockly"
        link = LocklyLink(self.hass, address=self._address, name=name, creds=creds)
        try:
            await link.async_refresh()
        except CredentialError:
            return await self._async_failed("cloud_wrong_lock")
        except UnsupportedModel as err:
            return self.async_abort(
                reason="unsupported_model", description_placeholders={"error": str(err)}
            )
        except LocklyError as err:
            _LOGGER.debug("could not reach the lock: %s", err)
            return await self._async_failed("cannot_connect")
        finally:
            await link.async_stop()
        self._locks = []
        return self.async_create_entry(
            title=name,
            data={
                CONF_ADDRESS: self._address,
                CONF_LOCK_NAME: name,
                CONF_MASTER_CODE: creds.master_code,
                CONF_LOCK_UUID: creds.uuid.hex(),
                CONF_HOUSE_CODE: creds.house_code,
            },
        )

    async def _async_failed(self, error: str) -> ConfigFlowResult:
        """Back to the lock list if there is another to try, else to sign-in."""
        if len(self._locks) > 1:
            return await self.async_step_pick_lock(errors={"base": error})
        self._locks = []
        return self._show_cloud({"base": error})
