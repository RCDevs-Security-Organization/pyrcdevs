Welcome to pyrcdevs's documentation!
====================================

Usage examples
--------------

Manager API (requesting Server_Status method)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   from pyrcdevs import WebADMManager

   webadm_manager_api = WebADMManager(
       "my_webadm_host_or_ip", "443", "UserDomain\\api_username", "api_password", "/path/to/ca_file.crt"
   )
   server_status_response = webadm_manager_api.server_status(servers=True, websrvs=True, webapps=True)

Output is:

.. code:: python

   {'version': '2.3.24', 'servers': {'ldap': True, 'sql': True, 'session': True, 'pki': True, 'mail': True}, 'webapps': {'HelpDesk': {'version': '1.1.5', 'status': 'Invalid'}, 'OpenID': {'version': '1.6.7', 'status': 'Invalid'}, 'PwReset': {'version': '1.3.4', 'status': 'Ok'}, 'SelfDesk': {'version': '1.4.7', 'status': 'Ok'}, 'SelfReg': {'version': '1.4.4', 'status': 'Ok'}}, 'websrvs': {'OpenOTP': {'version': '2.2.22', 'status': 'Ok', 'license': 'Ok'}, 'SMSHub': {'version': '1.3.1', 'status': 'Ok'}, 'SpanKey': {'version': '2.1.5', 'status': 'Ok', 'license': 'Ok'}}, 'status': False}

With TLS client authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TLS client authentication may be required if your WebADM server has the
``manager_auth`` setting configured to ``PKI`` in
``/opt/webadm/conf/webadm.conf`` file.

In this case, you can set the p12_file and p12_password options when
instantiating the WebADM object:

.. code:: python

   from pyrcdevs import WebADMManager

   webadm_manager_api = WebADMManager(
       "my_webadm_host_or_ip",
       "443",
       "UserDomain\\api_username",
       "api_password",
       "/path/to/ca_file.crt",
       p12_file_path="/path/to/p12_file.p12",
       p12_password="p12_PasSW0rd"
   )
   server_status_response = webadm_manager_api.server_status()

SOAP API (requesting openotpNormalLogin method)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   from pyrcdevs import OpenOTPSoap

   openotp_soap_api = OpenOTPSoap(
       "my_webadm_host_or_ip", "8443", "/path/to/ca_file.crt"
   )
   response = openotp_soap_api.normal_login("testuser1", ldap_password="password", otp_password="123456")

Output is:

.. code:: python

   {'code': '1', 'error': None, 'message': 'Authentication success', 'data': None, 'concat': '0'}

With Authentication
~~~~~~~~~~~~~~~~~~~

Authentication may be required if your SOAP endpoint has the
``Require Certificate / API Key`` setting configured to ``Yes`` in its
settings. This setting is located in WebADM under
``Applications->Configure`` page of corresponding web service.

Client certificate
^^^^^^^^^^^^^^^^^^

For client certiticate authentication, you can set
the p12_file and p12_password options when instantiating the OpenOTPSoap
object:

.. code:: python

   from pyrcdevs import OpenOTPSoap

   openotp_soap_api = OpenOTPSoap(
       "my_webadm_host_or_ip",
       "443",
       "/path/to/ca_file.crt",
       p12_file_path="/path/to/p12_file.p12",
       p12_password="p12_PasSW0rd"
   )
   response = openotp_soap_api.normal_login("testuser1", ldap_password="password", otp_password="123456")

With API key
^^^^^^^^^^^^

For API key authentication, you can set the api_key parameter when
instantiating the OpenOTPSoap object:

.. code:: python

   from pyrcdevs import OpenOTPSoap

   openotp_soap_api = OpenOTPSoap(
       "my_webadm_host_or_ip",
       "443",
       "/path/to/ca_file.crt",
       api_key="5860687476061196336_d788fd99ea4868f35c3b5e21ada3920b9501bb2c",
   )
   response = openotp_soap_api.normal_login("testuser1", ldap_password="password", otp_password="123456")




Package description
===================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules
      
   
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`