"""This module implements OpenOTP API Manager."""

import ssl
from enum import Enum
from typing import Any

from pyrcdevs.manager.Manager import Manager


class HOTPURIDigits(Enum):
    """Enum for possible number of HOTP digits."""

    O6 = 6
    O8 = 8
    O10 = 10


class TOTPURIDigits(Enum):
    """Enum for possible number of TOTP digits."""

    O6 = 6
    O8 = 8
    O10 = 10


class ListRegisterSize(Enum):
    """Enum for size specifying the amount of OTPs to be created in the List."""

    I25 = 25
    I50 = 50
    I100 = 100
    I250 = 250
    I500 = 500
    I1000 = 1000


class ListRegisterAlgo(Enum):
    """Enum for algorithm of OTPs to be created in the List."""

    ISHA1 = "SHA1"
    ISHA256 = "SHA256"
    ISHA512 = "SHA512"


class AppKeyRegisterLength(Enum):
    """Enum for app keys registration length."""

    P10 = 10
    P15 = 15
    P20 = 20
    P25 = 25
    P30 = 30


class OpenOTPManager(Manager):
    """API manag class for OpenOTP endpoint."""

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
        Construct OpenOTPManager class.

        :param str host: path to the db file
        :param str username: username for API authentication
        :param str password: password for API authentication
        :param int port: listening port of OpenOTP server
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

    async def appkey_fetch(self, dn) -> list:
        """
        Retrieve the Application Passwords.

        Returns the Application Passwords in an array containing the passwords per Client ID.

        :param str dn:
        :return: Application Passwords in an array containing the passwords per Client ID.
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.AppKey_Fetch", params
        )
        return response

    async def appkey_register(self, dn, length=None, expires=None) -> bool:
        """
        Register Application Passwords.

        Initializes Application Passwords for the user (bypassing usual factors).
        The length is the number of alphanumeric characters of the passwords.
        Expires indicates the number of days after which the passwords expire (max 1 year).
        If expiration is not set, it defaults to the configured expiration time.

        :param AppKeyRegisterLength length:
        :param int expires:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        if length is not None and not isinstance(length, AppKeyRegisterLength):
            raise TypeError("length type is not AppKeyRegisterLength")
        params = {"dn": dn}
        if length is not None:
            params["length"] = length
        if expires is not None:
            params["expires"] = expires
        response = await super().handle_api_manager_request(
            "OpenOTP.AppKey_Register", params
        )
        return response

    async def appkey_unregister(self, dn) -> bool:
        """
        Unregister the Application Passwords.

        Removes the registered Application Password from the user.

        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.AppKey_Unregister", params
        )
        return response

    async def block_check(self, dn) -> bool:
        """
        Check if user account is blocked.

        Returns true is the account is currently blocked and false if it is not.

        :param str dn:
        :return: true is the account is currently blocked and false if it is not.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.Block_Check", params
        )
        return response

    async def block_reset(self, dn) -> bool:
        """
        Unblock the user account.

        Removes any blocking state or blocking counter from the user.

        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.Block_Reset", params
        )
        return response

    async def block_start(self, dn, expires=None) -> bool:
        """
        Block the user account.

        Forces immediate blocking of the user.
        If expired is set then the blocking expires after the specified number of seconds (max 1 day).
        Otherwize the blocking is permanent and requires a manual unblocking.

        :param int expires:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if expires is not None:
            params["expires"] = expires
        response = await super().handle_api_manager_request(
            "OpenOTP.Block_Start", params
        )
        return response

    async def domain_report(
        self,
        domain,
        filter=None,
        settings=None,
        token=None,
        u2f=None,
        block=None,
        expire=None,
        reset=None,
    ) -> dict | bool:
        """
        Get Domain Statistics.

        Get statistics on user metadata and user settings for all users in the domain.
        If no search filter is defined then any extended user will be included in the output.
        If 'token' parameter is set to true then OTP Token information are returned.
        If 'u2f' parameter is set to true then U2F Device information are returned.
        If 'block' parameter is set to true then blocking information are returned.
        If 'expire' parameter is set to true then AD password expiration is returned.
        If 'reset' parameter is set to true then statistics are reseted.

        :param str domain:
        :param str filter:
        :param list settings:
        :param bool token:
        :param bool u2f:
        :param bool block:
        :param bool expire:
        :param bool reset:
        :return: array indexed with users' DN and containing the user statistics and returns false on error.
        :rtype: dict | bool
        """
        params = {"domain": domain}
        if filter is not None:
            params["filter"] = filter
        if settings is not None:
            params["settings"] = settings
        if token is not None:
            params["token"] = token
        if u2f is not None:
            params["u2f"] = u2f
        if block is not None:
            params["block"] = block
        if expire is not None:
            params["expire"] = expire
        if reset is not None:
            params["reset"] = reset
        response = await super().handle_api_manager_request(
            "OpenOTP.Domain_Report", params
        )
        return response

    async def emerg_register(self, dn, otp=None, expires=None, maxuse=None) -> Any:
        """
        Register an Emergency OTP.

        Registers an Emergency (temporary static) OTP for the user.
        The Emergency OTP must be alpha-numeric and length must be equal to the OTP length.
        When no provided, the Emergency OTP is generated and returned.
        The expires specifies for how many seconds the OTP is valid (between 5 mins and 1 days).
        The maxuse optionally specifies how many times the OTP can be used.
        Once expired, the Emergency OTP is automatically removed.

        :param str otp:
        :param int expires:
        :param int maxuse:
        :param str dn:
        :return: the OTP on success and false on error.
        :rtype: Any
        """
        params = {"dn": dn}
        if otp is not None:
            params["otp"] = otp
        if expires is not None:
            params["expires"] = expires
        if maxuse is not None:
            params["maxuse"] = maxuse
        response = await super().handle_api_manager_request(
            "OpenOTP.Emerg_Register", params
        )
        return response

    async def emerg_unregister(self, dn) -> bool:
        """
        Unregister the Emergency OTP.

        Removes the registered Emergency OTP from the user.

        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.Emerg_Unregister", params
        )
        return response

    async def expire_check(self, dn, id_=None) -> bool:
        """
        Check if the Token has expired.

        Returns true is the Token is currently expired and false if it is not.

        :param int id_:
        :param str dn:
        :return: true is the Token is currently expired and false if it is not.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Expire_Check", params
        )
        return response

    async def expire_reset(self, dn, id_=None) -> bool:
        """
        Unset the Token expiration.

        Removes the expiration date (if present) from a registered Token.
        The id indicates which Token is used if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Expire_Reset", params
        )
        return response

    async def expire_start(self, dn, expires=None, id_=None) -> bool:
        """
        Set the Token expiration.

        Add an expiration time for a registered Token.

        Expires indicates the number of days after which the Token will stop working (max 1 year).
        If expiration is not set, it defaults to the configured Token expiration time.

        :param int expires:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if expires is not None:
            params["expires"] = expires
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Expire_Start", params
        )
        return response

    async def fido_challenge(self, username, domain, random, appid=None) -> str:
        """
        Get a FIDO registration challenge.

        Returns a JSON-encoded U2F/FIDO2 registration challenge.

        :param str username:
        :param str domain:
        :param str random:
        :param str appid:
        :return: JSON-encoded U2F/FIDO2 registration challenge.
        :rtype: str
        """
        params = {"username": username, "domain": domain, "random": random}
        if appid is not None:
            params["appid"] = appid
        response = await super().handle_api_manager_request(
            "OpenOTP.FIDO_Challenge", params
        )
        return response

    async def fido_disable(self, dn, id_=None) -> bool:
        """
        De-activate the Device.

        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.FIDO_Disable", params
        )
        return response

    async def fido_enable(self, dn, id_=None) -> bool:
        """
        Re-activate the Device.

        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.FIDO_Enable", params
        )
        return response

    async def fido_register(self, dn, response, random, id_=None, name=None) -> bool:
        """
        Register an FIDO Device.

        The response should contain the output from the device converted to websafe-base64.
        The id indicates which Device is registered if multiple Devices are allowed.
        By default (when id is not set) the first Device is selected.

        :param str response:
        :param str random:
        :param int id_:
        :param str name:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "response": response, "random": random}
        if id_ is not None:
            params["id"] = id_
        if name is not None:
            params["name"] = name
        response = await super().handle_api_manager_request(
            "OpenOTP.FIDO_Register", params
        )
        return response

    async def fido_unregister(self, dn, id_=None) -> bool:
        """
        Unregister a FIDO Device.

        Un-registration removes the Device metadata from the user.
        The id indicates which Device is un-registered if multiple Devices are allowed.
        By default (when id is not set) the first Device is selected.

        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.FIDO_Unregister", params
        )
        return response

    async def hotp_register(self, dn, key, state=None, session=None, id_=None) -> bool:
        """
        Register a HOTP Token.

        The key is the Token binary random seed and must be base64-encoded.
        Key length can be:
        - 20 Bytes for a SHA1 OATH Token
        - 32 Bytes for a SHA256 OATH Token (not officially supported by RFC-4226)
        - 64 Bytes for a SHA512 OATH Token (not officially supported by RFC-4226)
        The initial counter value for a HOTP Token is generally '0'.
        The id indicates which Token is registered if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str dn: distinguished name of account
        :param str key: key is the Token binary random seed and must be base64-encoded.
        :param str state:
        :param str session:
        :param int id_:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "key": key}
        if state is not None:
            params["state"] = state
        if session is not None:
            params["session"] = session
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.HOTP_Register", params
        )
        return response

    async def hotp_resync_counter(self, dn, counter, id_=None) -> bool:
        """
        Resynchronize the HOTP Token with counter.

        The re-synchronization resets the Token counter to the specified value.
        It implies that you know the current counter value on the Token.

        :param int counter: new counter value
        :param int id_: slot id
        :param str dn: distinguished name of account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "counter": counter}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.HOTP_Resync_Counter", params
        )
        return response

    async def hotp_resync_sequence(self, dn, otp1, otp2, id_=None) -> bool:
        """
        Resynchronize the HOTP Token with OTPs.

        The re-synchronization recovers the Token counter value based on OTP values.
        You must provide two consecutive OTPs generated on the Token.

        :param int otp1: first OTP
        :param int otp2: second OTP
        :param int id_: slot id
        :param str dn: distinguished name of account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "otp1": otp1, "otp2": otp2}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.HOTP_Resync_Sequence", params
        )
        return response

    async def hotp_uri(
        self,
        name,
        key,
        userid,
        domain,
        state=None,
        digits=None,
        session=None,
        tinyurl=None,
    ) -> str:
        """
        Get a HOTP mobile URI.

        Returns the enrolment URI to be used in a QRCode.
        Name is the display name for the software Token.

        :param str name: display name for the software Token.
        :param str key: key is the Token binary random seed and must be base64-encoded.
        :param str userid: username of user account
        :param str domain: domain of user account
        :param str state: state of token
        :param HOTPURIDigits digits: number of digits for OTP code (see HOTPURIdigits for possible values)
        :param str session: mobile session
        :param bool tinyurl: if True, returned URL will be in short format
        :return: enrolment URI to be used in a QRCode
        :rtype: str
        """
        if digits is not None and not isinstance(digits, HOTPURIDigits):
            raise TypeError("digits type is not HOTPURIDigits")
        params = {"name": name, "key": key, "userid": userid, "domain": domain}
        if state is not None:
            params["state"] = state
        if digits is not None:
            params["digits"] = str(digits.value)
        if session is not None:
            params["session"] = session
        if tinyurl is not None:
            params["tinyurl"] = str(tinyurl)
        response = await super().handle_api_manager_request("OpenOTP.HOTP_URI", params)
        return response

    async def hotp_verify(self, otp, key, length, state=None) -> Any:
        """
        Verify HOTP Password.

        Check the displayed OTP is correct before registering the TOTP Token.

        :param str otp: OTP code
        :param str key: key is the Token binary random seed and must be base64-encoded.
        :param int length:
        :param str state:
        :return: Token state on success and false on error.
        :rtype: Any
        """
        params = {"otp": otp, "key": key, "length": length}
        if state is not None:
            params["state"] = state
        response = await super().handle_api_manager_request(
            "OpenOTP.HOTP_Verify", params
        )
        return response

    async def inventory_register(self, dn, serial, id_=None, otp=None) -> bool:
        """
        Register an inventoried Token.

        Inventoried hardware Tokens can be registered with their serial number.
        The serial corresponds to the 'Reference' field in the WebADM Token Inventory database.
        If 'otp' is present the the current OTP is checked before registering the Token.
        With inventoried Yubikey, serial can be the Yubikey modhex input prepended by the public ID.

        :param str dn:
        :param str serial:
        :param int id_:
        :param str otp:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "serial": serial}
        if id_ is not None:
            params["id"] = id_
        if otp is not None:
            params["otp"] = otp
        response = await super().handle_api_manager_request(
            "OpenOTP.Inventory_Register", params
        )
        return response

    async def list_fetch(self, dn) -> list:
        """
        Retrieve the OTP List.

        :param str dn:
        :return: OTP List in an array containing all the OTP values in sequence.
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.List_Fetch", params
        )
        return response

    async def list_register(self, dn, size=None, algo=None) -> bool:
        """
        Register an OTP List.

        Initializes an OTP List for the user.
        The size specifies the amount of OTPs to be created in the List.
        The algorithm should always be SHA1.

        :param ListRegisterSize size:
        :param ListRegisterAlgo algo:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        if size is not None and not isinstance(size, ListRegisterSize):
            raise TypeError("size type is not ListRegisterSize")
        if algo is not None and not isinstance(algo, ListRegisterAlgo):
            raise TypeError("size type is not ListRegisterAlgo")
        params = {"dn": dn}
        if size is not None:
            params["size"] = size
        if algo is not None:
            params["algo"] = algo
        response = await super().handle_api_manager_request(
            "OpenOTP.List_Register", params
        )
        return response

    async def list_state(self, dn) -> int:
        """
        Get the number of remaining OTPs.

        Returns the Id (current OTP offset) in the OTP List.
        If the return value is equal to the OTP List size then the OTP List is expired.

        :param str dn:
        :return: Id (current OTP offset) in the OTP List.
        :rtype: int
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.List_State", params
        )
        return response

    async def list_unregister(self, dn) -> bool:
        """
        Unregister the OTP List.

        Removes the registered OTP List from the user.

        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.List_Unregister", params
        )
        return response

    async def mobile_response(self, session) -> int:
        """
        Get the Status of the mobile session.

        The returned statuses are:
        0: The mobile session has failed or expired
        1: OpenOTP successfully received the mobile data
        2: OpenOTP did not received the mobile data yet

        :param str session: session ID
        :return: status of mobile session
        :rtype: int
        """
        params = {"session": session}
        response = await super().handle_api_manager_request(
            "OpenOTP.Mobile_Response", params
        )
        return response

    async def mobile_session(self, timeout, pincode=None, dn=None) -> Any:
        """
        Start a mobile enrolment session.

        Initialize a mobile communication session when mobile Push is enabled.
        The timeout (in seconds) must be long enough for the Token to enrol the provided QRCode.

        :param int timeout: in seconds, must be long enough for the Token to enrol the provided QRCode.
        :param str pincode: a pincode to protect QR code
        :param str dn: distinguished name of account
        :return: the session ID on success and NULL on error.
        :rtype: Any
        """
        params = {"timeout": timeout}
        if dn is not None:
            params["dn"] = dn
        if pincode is not None:
            params["pincode"] = pincode
        response = await super().handle_api_manager_request(
            "OpenOTP.Mobile_Session", params
        )
        return response

    async def ocra_register(self, dn, key, pin=None, state=None, id_=None) -> bool:
        """
        Register an OCRA Token.

        The key is the Token binary random seed and must be base64-encoded.
        Key length can be:
        - 20 Bytes for a SHA1 OATH Token
        - 32 Bytes for a SHA256 OATH Token
        - 64 Bytes for a SHA512 OATH Token
        The pin is needed with OCRA Suites having a PIN component (with 'P' flag).
        The counter value is valid only for event-based OCRA Suites (with 'C' flag).
        The id indicates which Token is registered if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str key:
        :param str pin:
        :param str state:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "key": key}
        if pin is not None:
            params["pin"] = pin
        if state is not None:
            params["state"] = state
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.OCRA_Register", params
        )
        return response

    async def ocra_resync_counter(self, dn, counter, id_=None) -> bool:
        """
        Resynchronize the OCRA Token with counter.

        This re-synchronization method is for event-based OCRA Suites (with 'C' flag).
        Look at method 'HOTP_Resync_Counter' above for details.

        :param int counter:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "counter": counter}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.OCRA_Resync_Counter", params
        )
        return response

    async def ocra_resync_sequence(self, dn, otp1, otp2, challenge, id_=None) -> bool:
        """
        Resynchronize the OCRA Token with OTPs.

        This re-synchronization method is for event-based OCRA Suites (with 'C' flag).
        Look at method 'HOTP_Resync_Sequence' above for details.

        :param int otp1:
        :param int otp2:
        :param str challenge:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "otp1": otp1, "otp2": otp2, "challenge": challenge}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.OCRA_Resync_Sequence", params
        )
        return response

    async def ocra_resync_time(self, dn, otp, challenge, id_=None) -> bool:
        """
        Resynchronize the OCRA Token with timestamp.

        This re-synchronization method is for time-based OCRA Suites (with 'T' flag).
        Look at method 'TOTP_Resync' above for details.

        :param int otp:
        :param str challenge:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "otp": otp, "challenge": challenge}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.OCRA_Resync_Time", params
        )
        return response

    async def ocra_setpin(self, dn, pin, id_=None) -> bool:
        """
        Set PIN code for the OCRA Token.

        Sets a new PIN code value for OCRA Suites having a PIN code component (with 'P' flag).
        The PIN must be alpha-numeric and length must be between 4 and 64 characters.

        :param str pin:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "pin": pin}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.OCRA_Setpin", params
        )
        return response

    async def prefix_register(self, dn, prefix=None) -> Any:
        """
        Register an OTP PIN Prefix.

        Registers an OTP Prefix (PIN Password) for the user.
        The OTP Prefix must be alpha-numeric and length must be between 4 and 64 characters.
        When no provided, the PIN Prefix is generated and returned.
        This is effective only if the 'Require OTP PIN Prefix' is enabled.

        :param str prefix:
        :param str dn:
        :return: PIN Prefix on success and false on error.
        :rtype: Any
        """
        params = {"dn": dn}
        if prefix is not None:
            params["prefix"] = prefix
        response = await super().handle_api_manager_request(
            "OpenOTP.Prefix_Register", params
        )
        return response

    async def prefix_unregister(self, dn) -> bool:
        """
        Unregister the OTP PIN Prefix.

        Removes the registered OTP Prefix from the user.

        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.Prefix_Unregister", params
        )
        return response

    async def totp_register(self, dn, key, state=None, session=None, id_=None) -> bool:
        """
        Register a TOTP Token.

        The key is the Token binary random seed and must be base64-encoded.
        Key length can be:
        - 20 Bytes for a SHA1 OATH Token
        - 32 Bytes for a SHA256 OATH Token
        - 64 Bytes for a SHA512 OATH Token
        The id indicates which Token is registered if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str key: key is the Token binary random seed and must be base64-encoded.
        :param str state:
        :param str session: mobile session ID
        :param int id_: slot id
        :param str dn: distinguished name of account
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "key": key}
        if state is not None:
            params["state"] = state
        if session is not None:
            params["session"] = session
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.TOTP_Register", params
        )
        return response

    async def totp_resync(self, dn, otp, id_=None) -> bool:
        """
        Resynchronize the TOTP Token.

        Some TOTP Tokens tend to get an internal clock drift by time and do not work anymore.
        The re-synchronization computes and stores the time drift between the server and the Token.
        The current and accurate OTP value on the Token is needed.

        :param str dn:
        :param int otp:
        :param int id_:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "otp": otp}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.TOTP_Resync", params
        )
        return response

    async def totp_uri(
        self,
        name,
        key,
        userid,
        domain,
        period=None,
        digits=None,
        session=None,
        tinyurl=None,
    ) -> str:
        """
        Get a TOTP mobile URI.

        Returns the enrolment URI to be used in a QRCode.
        Name is the display name for the software Token.

        :param str name: display name for the software Token.
        :param str key: key is the Token binary random seed and must be base64-encoded.
        :param int period: OTP period
        :param TOTPURIDigits digits: number of digits for OTP code (see TOTPURIDigits for possible values)
        :param str userid: username of user account
        :param str domain: domain of user account
        :param str session: mobile session ID
        :param bool tinyurl: if True, returned URL will be in short format
        :return: enrolment URI to be used in a QRCode.
        :rtype: str
        """
        if digits is not None and not isinstance(digits, TOTPURIDigits):
            raise TypeError("digits type is not TOTPURIDigits")
        params = {"name": name, "key": key, "userid": userid, "domain": domain}
        if period is not None:
            params["period"] = str(period)
        if digits is not None:
            params["digits"] = str(digits.value)
        if session is not None:
            params["session"] = session
        if tinyurl is not None:
            params["tinyurl"] = str(tinyurl)
        response = await super().handle_api_manager_request("OpenOTP.TOTP_URI", params)
        return response

    async def totp_verify(self, otp, key, length, period, state=None) -> str:
        """
        Verify TOTP Password.

        Check the displayed OTP is correct before registering the TOTP Token.
        Returns the Token state on success and false on error.

        :param str otp:
        :param str key:
        :param int length:
        :param int period:
        :param str state:
        :return:
        :rtype: str
        """
        params = {"otp": otp, "key": key, "length": length, "period": period}
        if state is not None:
            params["state"] = state
        response = await super().handle_api_manager_request(
            "OpenOTP.TOTP_Verify", params
        )
        return response

    async def tmpkey_register(self, dn, password, expires=None) -> bool:
        """
        Register Temporary Password.

        Initializes Temporary Passwords for the user (bypassing usual factors).
        The password length must be between 10 and 30 characters.
        Expires indicates the number of minutes after which the password expires (max 24 hours).
        If expiration is not set, it defaults to the configured expiration time.

        :param str password:
        :param int expires:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "password": password}
        if expires is not None:
            params["expires"] = expires
        response = await super().handle_api_manager_request(
            "OpenOTP.TmpKey_Register", params
        )
        return response

    async def tmpkey_unregister(self, dn) -> bool:
        """
        Unregister the Temporary Password.

        Removes the registered Temporary Password from the user.

        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.TmpKey_Unregister", params
        )
        return response

    async def token_disable(self, dn, id_=None) -> bool:
        """
        De-activate the Token.

        Mark the Token as disabled to temporarily/permanently de-activate it.
        The id indicates which Token is disabled if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str dn:
        :param int id_:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Token_Disable", params
        )
        return response

    async def token_enable(self, dn, id_=None) -> bool:
        """
        Re-activate the Token.

        Re-activate a disabled Token to make it usable again.
        The id indicates which Token is enabled if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str dn:
        :param int id_:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Token_Enable", params
        )
        return response

    async def token_unregister(self, dn, id_=None) -> bool:
        """
        Unregister an OTP Token.

        Un-registration removes the Token metadata from the user.
        The id indicates which Token is un-registered if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str dn:
        :param int id_:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Token_Unregister", params
        )
        return response

    async def user_devices(self, dn) -> list:
        """
        Get User FIDO Devices.

        Get the list of FIDO Devices available for a user.

        :param str dn:
        :return: array containing the available device details and false on error.
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.User_Devices", params
        )
        return response

    async def user_methods(self, dn, active=None) -> list:
        """
        Get User OTP Methods.

        Get the list of OTP methods available for a user.
        if 'active' parameter is set to true then only the user OTPType and OTPFallback are returned.

        :param str dn:
        :param bool active:
        :return: array containing the available methods and false on error.
        :rtype: list
        """
        params = {"dn": dn}
        if active is not None:
            params["active"] = active
        response = await super().handle_api_manager_request(
            "OpenOTP.User_Methods", params
        )
        return response

    async def user_report(
        self, dn, token=None, u2f=None, block=None, expire=None, reset=None
    ) -> Any:
        """
        Get User Statistics.

        Get statistics on user metadata and user settings.
        If 'token' parameter is set to true then OTP Token information are returned.
        If 'u2f' parameter is set to true then U2F Device information are returned.
        If 'block' parameter is set to true then blocking information are returned.
        If 'expire' parameter is set to true then AD password expiration is returned.
        If 'reset' parameter is set to true then statistics are reseted.

        :param str dn:
        :param bool token:
        :param bool u2f:
        :param bool block:
        :param bool expire:
        :param bool reset:
        :return: array containing the user statistics and returns false on error.
        :rtype: Any
        """
        params = {"dn": dn}
        if token is not None:
            params["token"] = token
        if u2f is not None:
            params["u2f"] = u2f
        if block is not None:
            params["block"] = block
        if expire is not None:
            params["expire"] = expire
        if reset is not None:
            params["reset"] = reset
        response = await super().handle_api_manager_request(
            "OpenOTP.User_Report", params
        )
        return response

    async def user_tokens(self, dn) -> list:
        """
        Get User OTP Tokens.

        Get the list of OTP Tokens registered for a user.

        :param str dn:
        :return: array containing the available token details and false on error.
        :rtype: list
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "OpenOTP.User_Tokens", params
        )
        return response

    async def voice_register(self, sample, model=None) -> Any:
        """
        Register Voice fingerprint.

        The voice sample must be a 16 Khz mono WAV audio stream in base64.

        Returns true on success, false on failure and voice model if other register calls are needed.

        :param str sample:
        :param str model:
        :return: true on success, false on failure and voice model if other register calls are needed.
        :rtype: Any
        """
        params = {"sample": sample}
        if model is not None:
            params["model"] = model
        response = await super().handle_api_manager_request(
            "OpenOTP.Voice_Register", params
        )
        return response

    async def yubicloud_register(self, dn, otp, id_=None) -> bool:
        """
        Register a Yubikey with YubiCloud.

        The OTP is the Yubikey generated string.
        The id indicates which Token is registered if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str otp:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "otp": otp}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Yubicloud_Register", params
        )
        return response

    async def yubikey_locate(self, otp, dn) -> int:
        """
        Locate the Yubikey Token.

        Get the registration index (from 1 to 10) for a registered Yubikey.

        :param str dn:
        :param str otp:
        :return: Yubikey registration index or 0 when not found.
        :rtype: int
        """
        params = {"dn": dn, "otp": otp}
        response = await super().handle_api_manager_request(
            "OpenOTP.Yubikey_Locate", params
        )
        return response

    async def yubikey_register(
        self, dn, key, secret, public, state=None, id_=None
    ) -> bool:
        """
        Register a Yubikey Token.

        The key is the Yubikey binary random seed (or secret) and must be base64-encoded.
        The key length must be 16 Bytes.
        The secret is the Yubikey binary Private Id and must be base64-encoded.
        The public is the Yubikey binary Public Id and must be converted from ModHex to base64.
        The id indicates which Token is registered if multiple Tokens are allowed.
        By default (when id is not set) the primary Token is selected.

        :param str key:
        :param str secret:
        :param str public:
        :param str state:
        :param int id_:
        :param str dn:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "key": key, "secret": secret, "public": public}
        if state is not None:
            params["state"] = state
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTP.Yubikey_Register", params
        )
        return response

    async def yubikey_reset(self, dn, id_=None) -> bool:
        """
        Reset the Yubikey Token.

        The reset simply removes the Token state value from the user.

        :param str dn:
        :param int id_:
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        if id_ is not None:
            params["id"] = id_
        response = await super().handle_api_manager_request(
            "OpenOTPManager.Yubikey_Reset", params
        )
        return response
