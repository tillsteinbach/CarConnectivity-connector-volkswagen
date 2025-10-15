

# CarConnectivity Connector for Volkswagen Vehicles
[![GitHub sourcecode](https://img.shields.io/badge/Source-GitHub-green)](https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/tillsteinbach/CarConnectivity-connector-volkswagen)](https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/releases/latest)
[![GitHub](https://img.shields.io/github/license/tillsteinbach/CarConnectivity-connector-volkswagen)](https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/tillsteinbach/CarConnectivity-connector-volkswagen)](https://github.com/tillsteinbach/CarConnectivity-connector-volkswagen/issues)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/carconnectivity-connector-volkswagen?label=PyPI%20Downloads)](https://pypi.org/project/carconnectivity-connector-volkswagen/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/carconnectivity-connector-volkswagen)](https://pypi.org/project/carconnectivity-connector-volkswagen/)
[![Donate at PayPal](https://img.shields.io/badge/Donate-PayPal-2997d8)](https://www.paypal.com/donate?hosted_button_id=2BVFF5GJ9SXAJ)
[![Sponsor at Github](https://img.shields.io/badge/Sponsor-GitHub-28a745)](https://github.com/sponsors/tillsteinbach)


## CarConnectivity will become the successor of [WeConnect-python](https://github.com/tillsteinbach/WeConnect-python) in 2025 with similar functionality but support for other brands beyond Volkswagen!

[CarConnectivity](https://github.com/tillsteinbach/CarConnectivity) is a python API to connect to various car services. This connector enables the integration of volkswagen vehicles through the WeConnect API. Look at [CarConnectivity](https://github.com/tillsteinbach/CarConnectivity) for other supported brands.

## Configuration
In your carconnectivity.json configuration add a section for the volkswagen connector like this:
```
{
    "carConnectivity": {
        "connectors": [
            {
                "type": "volkswagen",
                "config": {
                    "username": "test@test.de",
                    "password": "testpassword123"
                }
            }
        ]
    }
}
```
### Credentials
If you do not want to provide your username or password inside the configuration you have to create a ".netrc" file at the appropriate location (usually this is your home folder):
```
# For WeConnect
machine volkswagen
login test@test.de
password testpassword123
```
In this case the configuration needs to look like this:
```
{
    "carConnectivity": {
        "connectors": [
            {
                "type": "volkswagen",
                "config": {
                }
            }
        ]
    }
}
```

You can also provide the location of the netrc file in the configuration.
```
{
    "carConnectivity": {
        "connectors": [
            {
                "type": "volkswagen",
                "config": {
                    "netrc": "/some/path/on/your/filesystem"
                }
            }
        ]
    }
}
```
The optional S-PIN needed for some commands can be provided in the account section of the netrc:
```
# For WeConnect
machine volkswagen
login test@test.de
password testpassword123
account 1234
```
### Limitations
The connector is not working with US based vehicles. If you are looking for a connector for your Volkswagen in North America, use this connector instead: [CarConnectivity-connector-volkswagen-na](https://github.com/zackcornelius/CarConnectivity-connector-volkswagen-na)
