"""This module implements WebADM API Manager."""

import ssl
from enum import Enum
from typing import Any

from pyrcdevs.constants import MSG_NOT_RIGHT_TYPE
from pyrcdevs.manager.Manager import Manager


class LDAPSearchScope(Enum):
    """Enum for scopes of a LDAP search."""

    SUB = "sub"
    BASE = "base"
    ONE = "one"


class InventoryStatus(Enum):
    """Enum for statuses of inventory."""

    VALID = "Valid"
    LOST = "Lost"
    BROKEN = "Broken"
    EXPIRED = "Expired"


class UnlockApplication(Enum):
    """Enum for applications which can be unlocked."""

    SELFDESK = "selfdesk"
    PWRESET = "pwreset"
    SELFREG = "selfreg"
    OPENID = "openid"


class AutoConfirmApplication(Enum):
    """Enum for applications of auto confirmation mode of PKI."""

    OPENOTP = "openotp"
    OPENSSO = "opensso"
    SMSHUB = "smshub"
    SPANKEY = "spankey"


class EventLogApplication(Enum):
    """Enum for applications of event logs."""

    OPENOTP = "openotp"
    OPENSSO = "opensso"
    SMSHUB = "smshub"
    SPANKEY = "spankey"


class ConfigObjectApplication(Enum):
    """Enum for applications of configuration objects."""

    OPENOTP = "openotp"
    OPENSSO = "opensso"
    SMSHUB = "smshub"
    SPANKEY = "spankey"
    SELFDESK = "selfdesk"
    PWRESET = "pwreset"
    SELFREG = "selfreg"
    OPENID = "openid"


class ConfigObjectType(Enum):
    """Enum for types of configuration objects."""

    DOMAINS = "domains"
    TRUSTS = "trusts"
    CLIENTS = "clients"
    WEBAPPS = "webapps"
    WEBSRVS = "websrvs"


class AutoConfirmExpiration(Enum):
    """Enum for possible durations for auto confirmation mode of PKI."""

    E0 = 0
    E1 = 1
    E5 = 5
    E10 = 10
    E15 = 15
    E30 = 30
    E60 = 60


class QRCodeFormat(Enum):
    """Enum for picture format of QR code."""

    GIF = "GIF"
    PNG = "PNG"
    JPG = "JPG"
    TXT = "TXT"


class QRCodeSize(Enum):
    """Enum for size of QR code."""

    S1 = 1
    S2 = 2
    S3 = 3
    S4 = 4
    S5 = 5
    S6 = 6
    S7 = 7
    S8 = 8
    S9 = 9
    S10 = 10


class QRCodeMargin(Enum):
    """Enum for possible marge size of QR code."""

    S0 = 0
    S1 = 1
    S2 = 2
    S3 = 3
    S4 = 4
    S5 = 5


class LicenseProduct(Enum):
    """Enum for product in license."""

    OPENOTP = "OpenOTP"
    SPANKEY = "SpanKey"


class ClientMode(Enum):
    """Enum for client policy modes."""

    DEFAULT = 0
    STEP_DOWN = 1
    STEP_UP = 2
    NO_ACCESS = 3


class LDAPSyncObjectType(Enum):
    """Enum for type of object for LDAP sync used for Tenant."""

    USER = "user"
    GROUP = "group"


class WebADMManager(Manager):
    """API manag class for WebADM endpoint."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        p12_file_path: str = None,
        p12_password: str = None,
        timeout: int = 30,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
        ca_file: str | None = None,
        vhost: str | None = None,
    ) -> None:
        """
        Construct WebADM class.

        :param str host: path to the db file
        :param str username: username for API authentication
        :param str password: password for API authentication
        :param int port: listening port of WebADM server
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        :param ssl.VerifyMode verify_mode: one of ssl.CERT_NONE, ssl.CERT_OPTIONAL or ssl.CERT_REQUIRED. Default to
        ssl.CERT_REQUIRED
        :param str | None ca_file: path to the CA file for validating server certificate
        :param str | None vhost: virtual host that will be set as value for Host HTTP header
        """
        super().__init__(
            host,
            username,
            password,
            p12_file_path,
            p12_password,
            timeout,
            port,
            verify_mode,
            ca_file,
            vhost,
        )

    async def activate_ldap_object(self, dn: str) -> bool:
        """
        Activate LDAP object.

        :param str dn: distinghuished name of user account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "Activate_LDAP_Object", params
        )
        return response

    async def cert_auto_confirm(
        self, expires, application=None, addresses=None
    ) -> bool:
        """
        Enable the auto configmation mode like in Admin / Issue Certificate.

        :param AutoConfirmExpiration expires: duration of auto confirm (see AutoConfirmExpiration for possible values)
        :param AutoConfirmApplication application: filter application (see AutoConfirmApplication for possible values)
        :param str addresses: filter addresses
        :return: true on success and false on error.
        :rtype: bool
        """
        if not isinstance(expires, AutoConfirmExpiration):
            raise TypeError("application type is not AutoConfirmExpiration")
        if application is not None and not isinstance(
            application, AutoConfirmApplication
        ):
            raise TypeError("application type is not AutoConfirmApplication")
        params = {"expires": expires.value}
        if application is not None:
            params["application"] = application.value
        if addresses is not None:
            params["addresses"] = addresses
        response = await super().handle_api_manager_request("Cert_Auto_Confirm", params)
        return response

    async def check_ldap_object(self, dn: str) -> bool:
        """
        Check if an object DN exists in LDAP.

        :param str dn: distinghuished name of user account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request("Check_LDAP_Object", params)
        return response

    async def check_user_active(self, dn) -> bool:
        """
        Return True if the user is activated (count one license).

        :param str dn: distinghuished name of user account.
        :return: True if user is activated
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request("Check_User_Active", params)
        return response

    async def check_user_badging(self, dn) -> bool:
        """
        Return the badging time if the user is badged-in.

        :param str dn: distinghuished name of user account.
        :return: True if user is badged-in.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "Check_User_Badging", params
        )
        return response

    async def check_user_password(self, dn, password) -> bool:
        """
        Check user password.

        :param str dn: distinghuished name of user account.
        :param str password: password to be checked.
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "password": password}
        response = await super().handle_api_manager_request(
            "Check_User_Password", params
        )
        return response

    async def clear_caches(self, type_=None, tenant=None) -> bool:
        """
        Trigger to the 'Clear WebADM System Caches' under the Admin menu.

        :param str type_: type of cache
        :param str tenant: tenant name for multi-tenant instances
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {}
        if type_ is not None:
            params["type"] = type_
        if tenant is not None:
            params["tenant"] = tenant
        response = await super().handle_api_manager_request("Clear_Caches", params)
        return response

    async def count_activated_hosts(self, product: LicenseProduct = None) -> int:
        """
        Return how many client hosts are currently counted by the licensing.

        If a product ID is provided, WebADM counts only the hosts which are in use for the product.

        :param LicenseProduct product: product ID
        :return: number of activated hosts
        :rtype: int
        """
        if product is not None and not isinstance(product, LicenseProduct):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("product", "LicenseProduct"))
        params = {}
        if product is not None:
            params["product"] = product.value
        response = await super().handle_api_manager_request(
            "Count_Activated_Hosts", params
        )
        return response

    async def count_activated_users(self, product: LicenseProduct = None) -> int:
        """
        Return how many activated users are currently counted by the licensing.

        If a product ID is provided, WebADM counts only the users which are in use for the product.

        :param LicenseProduct product: product ID
        :return: number of activated users
        :rtype: int
        """
        if product is not None and not isinstance(product, LicenseProduct):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("product", "LicenseProduct"))
        params = {}
        if product is not None:
            params["product"] = product.value
        response = await super().handle_api_manager_request(
            "Count_Activated_Users", params
        )
        return response

    async def count_domain_users(self, domain, active=None) -> int:
        """
        Return how many users or activated users are present in the domain subtree.

        :param domain: domain name
        :param active: if True, only Return activated users
        :return: number of activated users
        :rtype: int
        """
        params = {"domain": domain}
        if active is not None:
            params["active"] = active
        response = await super().handle_api_manager_request(
            "Count_Domain_Users", params
        )
        return response

    async def create_ldap_object(self, dn: str, attrs: dict) -> bool:
        """
        Create a LDAP object based on given attributes.

        When you create an object, all the required LDAP attributes must be set in the 'attrs' dict.

        The 'attrs' parameter must also contain an array of attributes with their values like:

        {
        'objectclass': ['person', 'inetorgperson'],
        'uid': ['myLogin'],
        'userpassword': ['myPassword'],
        'sn': ['myUser'}
        }

        You can use %AUTOINC% with uidnumber and gidnumber attributes.

        :param str dn: distinghuished name of user account
        :param dict attrs: dictionnary of attributes values (e.g. {"objectclass": ["webadmaccount", "person"]})
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "attrs": attrs}
        response = await super().handle_api_manager_request(
            "Create_LDAP_Object", params
        )
        return response

    async def deactivate_ldap_object(self, dn) -> bool:
        """
        Deactivate LDAP object.

        :param str dn: distinghuished name of user account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "Deactivate_LDAP_Object", params
        )
        return response

    async def get_config_objects(
        self,
        type_: ConfigObjectType,
        settings: bool = None,
        application: ConfigObjectApplication = None,
    ) -> list or dict:
        """
        Return configuration of WebADM objects.

        :param ConfigObjectType type_: type of object (see ConfigObjectType for possible values)
        :param bool settings: if True, Return all configuration details
        :param ConfigObjectApplication application: application name (see ConfigObjectApplication for possible values)
        :return: a list of object name if settings parameter is False or a dictionnary of object configuration if
        settings parameter is True
        :rtype: list | dict
        """
        if not isinstance(type_, ConfigObjectType):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("type_", "ConfigObjectType"))
        params = {"type": type_.value}
        if settings is not None:
            params["settings"] = settings
        if application is not None:
            if not isinstance(application, ConfigObjectApplication):
                raise TypeError(
                    MSG_NOT_RIGHT_TYPE.format("application", "ConfigObjectApplication")
                )
            params["application"] = application.value
        response = await super().handle_api_manager_request(
            "Get_Config_Objects", params
        )
        return response

    async def get_event_logs(
        self, application: EventLogApplication, max_: int = None, dn: str = None
    ) -> list:
        """
        Fetch SQL log events for the specified application.

        :param EventLogApplication application: application name (see EventLogApplication for possible values).
        :param int max_: number of log entries to be returned.
        :param dn: filter on a specific distinghuished name
        :return: list of log entries
        :rtype: list
        """
        if not isinstance(application, EventLogApplication):
            raise TypeError(
                MSG_NOT_RIGHT_TYPE.format("application", "EventLogApplication")
            )
        if max_ is not None and (not isinstance(max_, int) or max_ < 1):
            raise TypeError("max is not a positive int!")
        params = {"application": application.value}
        if max_ is not None:
            params["max"] = max_
        if dn is not None:
            params["dn"] = dn
        response = await super().handle_api_manager_request("Get_Event_Logs", params)
        return response

    async def get_license_details(self, product=None) -> dict:
        """
        Return license information like expiration, limitations, license server's pool state etc.

        :param LicenseProduct product: product ID
        :return: dictionnary of license details
        :rtype: dict
        """
        if product is not None and not isinstance(product, LicenseProduct):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("product", "LicenseProduct"))
        params = {}
        if product is not None:
            params["product"] = product.value
        response = await super().handle_api_manager_request(
            "Get_License_Details", params
        )
        return response

    async def get_qrcode(self, uri, size=None, margin=None, format_=None) -> str:
        """
        Return the QRCode image in the specified format for the given 'uri' string.

        :param str uri: URI which is converted to a QR Code
        :param QRCodeSize size: size of QR Code (see QRCodeSize enum for possible values)
        :param QRCodeMargin margin: marging of QR Code (see QRCodeMargin enum for possible values)
        :param QRCodeFormat format_: image format (e.g. PNG) of QR Code (see QRCodeFormat enum for possible values)
        :return: QR Code in base64 format
        :rtype: str
        """
        if size is not None and not isinstance(size, QRCodeSize):
            raise TypeError("size type is not QRCodeSize")
        if margin is not None and not isinstance(margin, QRCodeMargin):
            raise TypeError("margin type is not QRCodeMargin")
        if format_ is not None and not isinstance(format_, QRCodeFormat):
            raise TypeError("format type is not QRCodeFormat")
        params = {"uri": uri}
        if size is not None:
            params["size"] = size.value
        if margin is not None:
            params["margin"] = margin.value
        if format_ is not None:
            params["format"] = format_.value
        response = await super().handle_api_manager_request("Get_QRCode", params)
        return response

    async def get_random_bytes(self, length) -> str:
        """
        Return pseudo-random bytes ganerated by the WebADM true random engine.

        :param int length: length of random bytes
        :return: random bytes in base64 format
        :rtype: str
        """
        params = {"length": length}
        response = await super().handle_api_manager_request("Get_Random_Bytes", params)
        return response

    async def get_user_attrs(self, dn, attrs=None) -> dict:
        """
        Get user attributes.

        :param str dn: distinghuished name of user account.
        :param list attrs: list of attributes to be returned.
        :return: a dictionnary of values of attributes.
        :rtype: dict
        """
        params = {"dn": dn}
        if attrs is not None:
            params["attrs"] = attrs
        response = await super().handle_api_manager_request("Get_User_Attrs", params)
        return response

    async def get_user_certificates(self, dn) -> list:
        """
        Return an array of user certificates in PEM format.

        :param str dn: distinghuished name of user account.
        :return: list of user certificates in PEM format.
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "Get_User_Certificates", params
        )
        return response

    async def get_user_data(self, dn, data=None) -> dict:
        """
        Retrieve user application data from the configured webadm_data attribute(s).

        :param str dn: distinghuished name of user account.
        :param list data: list of data to be returned.
        :return: a dictionnary of values of data.
        :rtype: dict
        """
        params = {"dn": dn}
        if data is not None:
            params["data"] = data
        response = await super().handle_api_manager_request("Get_User_Data", params)
        return response

    async def get_user_dn(self, username: str, domain: str) -> str:
        """
        Return a user LDAP DN based on a username (UID) and WebADM domain name.

        :param str username: UID of account
        :param str domain: domain where account belongs to
        :rtype: str
        """
        params = {"username": username, "domain": domain}
        response = await super().handle_api_manager_request("Get_User_DN", params)
        return response

    async def get_user_domains(self, dn: str) -> list:
        """
        Return the list of WebADM domains the user is part of.

        :param str dn: distinghuished name of user account
        :return: list of user domains
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request("Get_User_Domains", params)
        return response

    async def get_user_groups(self, dn: str, domain: str) -> list:
        """
        Return the list of LDAP groups the user is part of.

        :param str dn: distinghuished name of user account
        :param str domain: domain of user account
        :return: list of user groups
        :rtype: list
        """
        params = {"dn": dn, "domain": domain}
        response = await super().handle_api_manager_request("Get_User_Groups", params)
        return response

    async def get_user_ids(self, dn: str) -> list:
        """
        Return the list of user login names (UID attribute values).

        :param str dn: distinghuished name of user account
        :return: list of user IDs
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request("Get_User_IDs", params)
        return response

    async def get_user_settings(self, dn, settings=None) -> dict:
        """
        Retrieve user application settings from the configured webadm_settings attribute(s).

        :param str dn: distinghuished name of user account.
        :param list settings: list of settings to be returned.
        :return: a dictionnary of values of settings.
        :rtype: dict
        """
        params = {"dn": dn}
        if settings is not None:
            params["settings"] = settings
        response = await super().handle_api_manager_request("Get_User_Settings", params)
        return response

    async def import_inventory_item(
        self, type_, reference, description, data, active=None, status=None
    ) -> bool:
        """
        Import new items to the inventory database.

        Data must be base64-encoded and set according to RCDevs inventory specification.

        :param str type_: type of the hardware token
        :param str reference: serial number of hardware token
        :param str description: description of hardware token
        :param dict data: dictionnary of token data (e.g. {"TokenType": "WVVCSUtFWQ==", "TokenID": "iXfEf9wE",
                          "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==", "DataMode": "Aw==", "TokenState": "NzY4"})
        :param bool active: if active is True, hardware token is activated
        :param InventoryStatus status: status of hardware token (see InventoryStatus enum for possible statuses)
        :return: true on success and false on error.
        :rtype: bool
        """
        if status is not None and not isinstance(status, InventoryStatus):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("status", "InventoryStatus"))
        params = {
            "type": type_,
            "reference": reference,
            "description": description,
            "data": data,
        }
        if active is not None:
            params["active"] = active
        if status is not None:
            params["status"] = status.value
        response = await super().handle_api_manager_request(
            "Import_Inventory_Item", params
        )
        return response

    async def link_inventory_item(self, type_, reference, dn=None) -> bool:
        """
        Link or unlink the item to a user DN (an empty DN means unlink).

        :param str type_: type of the hardware token
        :param str reference: serial number of hardware token
        :param str dn: distinghuished name of user account to be linked with token
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"type": type_, "reference": reference}
        if dn is not None:
            params["dn"] = dn
        response = await super().handle_api_manager_request(
            "Link_Inventory_Item", params
        )
        return response

    async def move_ldap_object(self, dn: str, container: str) -> bool:
        """
        Move a LDAP object.

        :param str dn: distinghuished name of user account
        :param str container: new container where to move object
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "container": container}
        response = await super().handle_api_manager_request("Move_LDAP_Object", params)
        return response

    async def remove_ldap_object(self, dn: str) -> bool:
        """
        Remove LDAP object based on DN.

        :param str dn: distinghuished name of user account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "Remove_LDAP_Object", params
        )
        return response

    async def remove_user_attrs(self, dn, attrs, values=None) -> bool:
        """
        Remove user attributes from account, or removes specific user attribute values from account.

        :param str dn: distinghuished name of user account.
        :param list|dict attrs: list of attributes to be removed. If values is set to True, this must be a dictionnary
        of specific attributes values to be removed (e.g. {"objectclass": ["webadmaccount", "person"]})
        :param bool values:  if true then only the specified attribute values are removed.
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "attrs": attrs}
        if values is not None:
            params["values"] = values
        response = await super().handle_api_manager_request("Remove_User_Attrs", params)
        return response

    async def remove_user_certificate(self, dn, certificate) -> bool:
        """
        Remove the user certificate with the specified PEM certificate.

        :param str dn: distinghuished name of user account.
        :param str certificate: certificate in PEM format.
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "certificate": certificate}
        response = await super().handle_api_manager_request(
            "Remove_User_Certificate", params
        )
        return response

    async def rename_ldap_object(self, dn: str, name: str) -> bool:
        """
        Rename a LDAP object.

        :param str dn: distinghuished name of user account
        :param str name: new name of object
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "name": name}
        response = await super().handle_api_manager_request(
            "Rename_LDAP_Object", params
        )
        return response

    async def search_inventory_items(
        self,
        type_: str,
        filter_: str = None,
        linked: bool = None,
        active: bool = None,
        status: InventoryStatus = None,
        start: str = None,
        stop: str = None,
    ) -> list:
        """
        Return the Inventory items (list of serial numbers) correspondind to the search parameters.

        :param str type_: type of the hardware token
        :param str filter_: filter on reference of hardware token
        :param bool linked: if linked us True, this only updates hardware token linked to a user.
        :param bool active: if active is True, hardware token is activated
        :param InventoryStatus status: status of hardware token (see InventoryStatus enum for possible statuses)
        :param str start: filter so that the import date is after the start time. Format for time is YYYY-MM-DD HH:MM:SS
        :param str stop: filter so that the import date is after the stop time. Format for time is YYYY-MM-DD HH:MM:SS
        :return: list of found hardware token serial numbers
        :rtype: list
        """
        if status is not None and not isinstance(status, InventoryStatus):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("status", "InventoryStatus"))
        params = {"type": type_}
        if filter_ is not None:
            params["filter"] = filter_
        if linked is not None:
            params["linked"] = linked
        if active is not None:
            params["active"] = active
        if status is not None:
            params["status"] = status.value
        if start is not None:
            params["start"] = start
        if stop is not None:
            params["stop"] = stop
        response = await super().handle_api_manager_request(
            "Search_Inventory_Items", params
        )
        return response

    async def search_ldap_objects(
        self,
        basedn: str,
        filter_: str = None,
        scope: LDAPSearchScope = None,
        attrs: list = None,
    ) -> dict:
        """
        Return the list of LDAP object corresponding to search criteria.

        By setting the 'attrs' parameter you can specify which LDAP attributes will be returned.
        Otherwise all LDAP attributes in the searched objects are returned.

        :param str basedn: base DN from where search applies.
        :param str filter_: LDAP filter (e.g. (objectclass=webadmaccount))
        :param LDAPSearchScope scope: search scope (sub,base,one)
        :param list attrs: list of attributes to be returned
        :return: dictionnary of LDAP objects
        :rtype: dict
        """
        if scope is not None and not isinstance(scope, LDAPSearchScope):
            raise TypeError("scope type is not LDAPSearchScope")
        params = {"basedn": basedn}
        if filter_ is not None:
            params["filter"] = filter_
        if scope is not None:
            params["scope"] = scope.value
        if attrs is not None:
            params["attrs"] = attrs
        response = await super().handle_api_manager_request(
            "Search_LDAP_Objects", params
        )
        return response

    async def send_mail(
        self, to, subject, body, from_=None, certificate=None, attachments=None
    ) -> bool:
        """
        Send an email to the specified recipient.

        :param str to: recipient of email
        :param str subject: subject of email
        :param str body: body of email
        :param str from_: sender of email
        :param str certificate: certificate of recipient so email is encrypted
        :param list attachments: list of file to attach to email
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"to": to, "subject": subject, "body": body}
        if from_ is not None:
            params["from"] = from_
        if certificate is not None:
            params["certificate"] = certificate
        if attachments is not None:
            params["attachments"] = attachments
        response = await super().handle_api_manager_request("Send_Mail", params)
        return response

    async def send_push(
        self, application, to, options=None, data=None, timeout=None
    ) -> bool:
        """
        Send a push notification to the specified recipient.

        :param str application: RCDevs' target mobile app name.
        :param str to: PlatformId:PushId of smartphone
        :param dict options: list of push options
        :param dict data: list of push data
        :param str timeout: timeout for push notification
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"application": application, "to": to}
        if options is not None:
            params["options"] = options
        if data is not None:
            params["data"] = data
        if timeout is not None:
            params["timeout"] = timeout
        response = await super().handle_api_manager_request("Send_Push", params)
        return response

    async def send_sms(self, to, message, from_=None) -> bool:
        """
        Send a SMS to the specified recipient.

        :param str to: recipient of SMS
        :param str message: content of SMS
        :param str from_: sender of SMS
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"to": to, "message": message}
        if from_ is not None:
            params["from"] = from_
        response = await super().handle_api_manager_request("Send_SMS", params)
        return response

    async def server_status(self, servers=None, webapps=None, websrvs=None) -> Any:
        """
        Return runtime health status for connectors, running applications.

        :param bool servers: if true then server connector statuses are included.
        :param bool webapps: if true then Web Application statuses are included.
        :param bool websrvs: if true then Web Service statuses are included.
        :rtype: Any
        """
        params = {}
        if servers is not None:
            params["servers"] = servers
        if webapps is not None:
            params["webapps"] = webapps
        if websrvs is not None:
            params["websrvs"] = websrvs
        response = await super().handle_api_manager_request("Server_Status", params)
        return response

    async def set_client_mode(
        self, client, mode, timeout=None, group=None, network=None
    ) -> bool:
        """
        Temporarly change a client policy's operating mode.

        :param str client: client name
        :param ClientMode mode: mode to set (see ClientMode enum for possible values)
        :param int timeout: timeout for change duration (in seconds)
        :param bool group: if True, change also applies to per-group policy
        :param bool network: if True, change also applies to per-network policy
        :return: true on success and false on error.
        :rtype: bool
        """
        if not isinstance(mode, ClientMode):
            raise TypeError("mode type is not ClientMode")
        params = {"client": client, "mode": mode.value}
        if timeout is not None:
            params["timeout"] = timeout
        if group is not None:
            params["group"] = group
        if network is not None:
            params["network"] = network
        response = await super().handle_api_manager_request("Set_Client_Mode", params)
        return response

    async def set_user_attrs(self, dn, attrs, values=None) -> bool:
        """
        Set user attribute values.

        :param str dn: distinghuished name of user account.
        :param dict attrs: dictionnary of attributes values (e.g. {"objectclass": ["webadmaccount", "person"]})
        :param values:  if set to true, then the new attribute values are added to exising ones.
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "attrs": attrs}
        if values is not None:
            params["values"] = values
        response = await super().handle_api_manager_request("Set_User_Attrs", params)
        return response

    async def set_user_data(self, dn, data) -> bool:
        """
        Set user data.

        :param str dn: distinghuished name of user account.
        :param dict data: dictionnary of data values (e.g. {'OpenOTP.LastLogin': 'MjAyMi0wNC0wOCAxMDo0MzowNQ=='})
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "data": data}
        response = await super().handle_api_manager_request("Set_User_Data", params)
        return response

    async def set_user_password(self, dn, password, change=None) -> bool:
        """
        Set user password.

        :param str dn: distinghuished name of user account
        :param str password: password to be set.
        :param bool change: set to True if the user must change the password at next logon with AD.
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "password": password}
        if change is not None:
            params["change"] = change
        response = await super().handle_api_manager_request("Set_User_Password", params)
        return response

    async def set_user_settings(self, dn, settings) -> bool:
        """
        Set user settings.

        :param str dn: distinghuished name of user account.
        :param dict settings: dictionnary of settings values (e.g. {'SpanKey.KeyType': 'RSA'})
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "settings": settings}
        response = await super().handle_api_manager_request("Set_User_Settings", params)
        return response

    async def sign_certificate_request(self, request, expires=None) -> str:
        """
        Return the locally signed certificate request (CSR) in PEM format.

        :param str request: certificate signing request in PEM format
        :param int expires: validity of the certificate (in days)
        :return: certificate in PEM format
        :rtype: str
        """
        params = {"request": request}
        if expires is not None:
            params["expires"] = expires
        response = await super().handle_api_manager_request(
            "Sign_Certificate_Request", params
        )
        return response

    async def sync_ldap_delete(self, container: str, contents: list) -> int or bool:
        """
        Synchronizes LDAP object removals in a tenant context.

        This method is used by RCDevs AD/LDAP sync utilities.

        :param str container: base DN on which apply delete
        :param list contents: list of objects to be excluded from deletion
        :return: the number of remaining objects on success and false on error.
        :rtype: int|bool
        """
        params = {"container": container, "contents": contents}
        response = await super().handle_api_manager_request("Sync_LDAP_Delete", params)
        return response

    async def sync_ldap_object(
        self, dn: str, attrs: dict, type_: LDAPSyncObjectType = None, uuid: str = None
    ) -> bool:
        """
        Synchronizes a remote LDAP object in a tenant context.

        This method is used by RCDevs AD/LDAP sync utilities.

        :param str dn: distinghuished name of user account
        :param dict attrs: dictionary of object attributes
        :param LDAPSyncObjectType type_: type of object (user or group) which is synchronized
        :param str uuid: Object GUID
        :return: true on success and false on error.
        :rtype: bool
        """
        if type_ is not None and not isinstance(type_, LDAPSyncObjectType):
            raise TypeError("type of type_ is not LDAPSyncObjectType")
        params = {"dn": dn, "attrs": attrs}
        if type_ is not None:
            params["type"] = type_.value
        if uuid is not None:
            params["uuid"] = uuid
        response = await super().handle_api_manager_request("Sync_LDAP_Object", params)
        return response

    async def unlock_application_access(self, dn, application, expires) -> bool:
        """
        Temporarly unlock user access for WebApps configured with 'Access Locked'.

        :param str dn: distinghuished name of user account
        :param UnlockApplication application: application name which is unlocked (see UnlockApplication enum for list
                                              of possible applications)
        :param expires: duration of application unlock (in seconds)
        :return: true on success and false on error.
        :rtype: bool
        """
        if not isinstance(application, UnlockApplication):
            raise TypeError("application type is not UnlockApplication")
        params = {"dn": dn, "application": application.value, "expires": expires}
        response = await super().handle_api_manager_request(
            "Unlock_Application_Access", params
        )
        return response

    async def update_inventory_items(
        self, type_, filter_=None, linked=None, active=None, status=None
    ) -> bool:
        """
        Update inventory status and active state for items matching the filter.

        :param str type_: type of the hardware token
        :param str filter_: filter on reference of hardware token
        :param bool linked: if linked us True, this only updates hardware token linked to a user.
        :param bool active: if active is True, hardware token is activated
        :param InventoryStatus status: status of hardware token (see InventoryStatus enum for possible statuses)
        :return: true on success and false on error.
        :rtype: bool
        """
        if status is not None and not isinstance(status, InventoryStatus):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("status", "InventoryStatus"))
        params = {"type": type_}
        if filter_ is not None:
            params["filter"] = filter_
        if linked is not None:
            params["linked"] = linked
        if active is not None:
            params["active"] = active
        if status is not None:
            params["status"] = status.value
        response = await super().handle_api_manager_request(
            "Update_Inventory_Items", params
        )
        return response
