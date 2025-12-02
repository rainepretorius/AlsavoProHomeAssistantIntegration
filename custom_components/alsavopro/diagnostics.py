"""Diagnostics support for the Alsavo Pro integration."""

from __future__ import annotations

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant

from .const import DOMAIN

TO_REDACT = {CONF_PASSWORD}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict:
    """Return diagnostic information for a config entry."""

    coordinator = hass.data[DOMAIN][entry.entry_id]
    handler = coordinator.data_handler

    return async_redact_data(
        {
            "entry": {
                "title": entry.title,
                "data": entry.data,
                "options": entry.options,
            },
            "debug": handler.diagnostic_data(),
        },
        TO_REDACT,
    )
