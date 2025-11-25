

# CarConnectivity Connector for Volkswagen Config Options
The configuration for CarConnectivity is a .json file.
## Volkswagen Connector Options
These are the valid options for the Volkswagen Connector
```json
{
    "carConnectivity": {
        "connectors": [
            {
                "type": "volkswagen", // Definition for the Volkswagen Connector
                "config": {
                    "log_level": "error", // set the connectos log level
                    "interval": 300, // Interval in which the server is checked in seconds
                    "username": "test@test.de", // Username of your Volkswagen Account
                    "password": "testpassword123", // Username of your Volkswagen Account
                    "spin": "1234", //S-Pin used for some special commands like locking/unlocking
                    "netrc": "~/.netr", // netrc file if to be used for passwords
                    "api_log_level": "debug", // Show debug information regarding the API
                    "max_age": 300, //Cache requests to the server vor MAX_AGE seconds
                    "force_enable_access": false, // Force enable 'access' in the capabilities, setting to true may bring the door status back if you don't have lock/unlock via the app (default: false)
                    "hide_vins": ["19XFB2F90CE040211", "1G2ZH35N074252067"] // Don't fetch these vins
                }
            }
        ],
        "plugins": []
    }
}
```
