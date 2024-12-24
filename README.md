# pyrcdevs


# Example (requesting Server_Status method)

```python
from pyrcdevs import WebADM

webadm_api_manager = WebADM(
    "my_webadm_host_or_ip", "443", "UserDomain\\api_username", "api_password", "/path/to/ca_file.crt"
)
server_status_response = webadm_api_manager.server_status(servers=True, websrvs=True, webapps=True)
```

Output is:
```json
{'version': '2.3.24', 'servers': {'ldap': True, 'sql': True, 'session': True, 'pki': True, 'mail': True}, 'webapps': {'HelpDesk': {'version': '1.1.5', 'status': 'Invalid'}, 'OpenID': {'version': '1.6.7', 'status': 'Invalid'}, 'PwReset': {'version': '1.3.4', 'status': 'Ok'}, 'SelfDesk': {'version': '1.4.7', 'status': 'Ok'}, 'SelfReg': {'version': '1.4.4', 'status': 'Ok'}}, 'websrvs': {'OpenOTP': {'version': '2.2.22', 'status': 'Ok', 'license': 'Ok'}, 'SMSHub': {'version': '1.3.1', 'status': 'Ok'}, 'SpanKey': {'version': '2.1.5', 'status': 'Ok', 'license': 'Ok'}}, 'status': False}

```

# TLS client authentication
TLS client authentication may be required if your WebADM server has the `manager_auth` setting configured to `PKI` in `/opt/webadm/conf/webadm.conf` file.

In this case, you can set the p12_file and p12_password options when instantiating the WebADM object:
```python
from pyrcdevs import WebADM

webadm_api_manager = WebADM(
    "my_webadm_host_or_ip", 
    "443", 
    "UserDomain\\api_username", 
    "api_password", 
    "/path/to/ca_file.crt",
    p12_file_path="/path/to/p12_file.p12",
    p12_password="p12_PasSW0rd"
)
server_status_response = webadm_api_manager.server_status()
```