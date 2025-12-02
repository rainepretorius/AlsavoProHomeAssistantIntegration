# Alsavo Pro / Swim & Fun / Artic Pro / Zealux ++ pool heatpump

Custom component for controlling pool heatpumps that uses the Alsavo Pro app in Home Assistant.

**Warning:** This is made by someone with no previous knowledge of Python and no knowledge of Home Assistant framework. And one could argue that both is still the case. Use this at your own risk, and please take backups!

If some adult with the proper knowledge could improve this, and maybe make it installable with HACS, please feel free to do so! 

## Install
#### Manually
In Home Assistant, create a folder under *custom_components* named *AlsavoPro* and copy all the content of this project to that folder.
Restart Home Assistant and go to *Devices and Services* and press *+Add integration*.
Search for *AlsavoPro* and add it.
#### HACS Custom Repository
In HACS, add a custom repository and use https://github.com/goev/AlsavoProHomeAssistantIntegration
Download from HACS.
Restart Home Assistant and go to *Devices and Services* and press *+Add integration*.
Search for *AlsavoPro* and add it.

## Configuration
You must now choose a name for the device. The serial number for the heat pump can be found in the Alsavo Pro app by logging in to the heat pump and pressing the Alsavo Pro-logo in the upper right corner.
Password is the same as the one you logged into the Alsavo Pro app with.

Ip-address and port can be one of two:
- If you want to use the cloud, set IP-address to 47.254.157.150 and port to 51192.
- If you want to bypass the cloud, enter the heat pumps ip-address and use port 1194.

## Debug logging
Enable debug logging in Home Assistant to capture the raw UDP traffic and parsed payloads. You can toggle this from the
integration's options ("Enable debug logging") or by configuring the logger directly:

```yaml
logger:
  default: info
  logs:
    custom_components.alsavopro: debug
```

With this configuration in `configuration.yaml`, the Home Assistant log will include the
connection handshake, query payloads, and parsed samples from the heat pump responses. You can also download an anonymized
diagnostics package (three-dots menu on the device) to share recent debug payload summaries without exposing your password.

## AlsavoCtrl
This code is very much based on AlsavoCtrl: https://github.com/strandborg/AlsavoCtrl
