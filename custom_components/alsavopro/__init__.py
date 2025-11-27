"""Alsavo Pro pool heat pump integration."""
import logging
from datetime import timedelta

import asyncio
import async_timeout
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from homeassistant.const import (
    CONF_PASSWORD,
    CONF_IP_ADDRESS,
    CONF_PORT,
    CONF_NAME,
)

from .AlsavoPyCtrl import AlsavoPro
from .const import (
    DOMAIN,
    SERIAL_NO,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass, config):
    return True


async def async_setup_entry(hass, entry):
    """Set up the Alsavo Pro heater."""
    name = entry.data.get(CONF_NAME)
    serial_no = entry.data.get(SERIAL_NO)
    ip_address = entry.data.get(CONF_IP_ADDRESS)
    port_no = entry.data.get(CONF_PORT)
    password = entry.data.get(CONF_PASSWORD)

    data_handler = AlsavoPro(name, serial_no, ip_address, port_no, password)
    data_coordinator = AlsavoProDataCoordinator(hass, data_handler)

    await data_coordinator.async_config_entry_first_refresh()

    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    hass.data[DOMAIN][entry.entry_id] = data_coordinator

    await hass.config_entries.async_forward_entry_setups(entry, ['sensor', 'climate'])

    return True


async def async_unload_entry(hass, config_entry):
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(
        config_entry, ["climate", "sensor"]
    )


class AlsavoProDataCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, data_handler):
        """Initialize my coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            # Name of the data. For logging purposes.
            name="AlsavoPro",
            # Polling interval. Will only be polled if there are subscribers.
            update_interval=timedelta(seconds=15),
        )
        self.data_handler = data_handler

    async def _async_update_data(self):
        _LOGGER.debug("_async_update_data")
        try:
            async with async_timeout.timeout(10):
                await self.data_handler.update()
                return self.data_handler
        except asyncio.TimeoutError as err:
            raise UpdateFailed("Timed out while communicating with Alsavo Pro heater") from err
        except Exception as err:  # pragma: no cover - best effort logging
            raise UpdateFailed(f"Unexpected error updating Alsavo Pro heater: {err}") from err
