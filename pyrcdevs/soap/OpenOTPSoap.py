"""This module implements OpenOTP SOAP API."""

import re
import ssl
from enum import Enum

from pyrcdevs.constants import MSG_NOT_RIGHT_TYPE, REGEX_BASE64, TYPE_BASE64_STRING
from pyrcdevs.soap.SOAP import SOAP


class QRCodeFormat(Enum):
    """Enum for possible QR code formats."""

    GIF = "GIF"
    PNG = "PNG"
    JPG = "JPG"
    TXT = "TXT"
    NONE = "NONE"


class SignatureMode(Enum):
    """Enum for possible signature modes."""

    AUTO = "auto"
    CaDES = "CADES"
    PaDES = "PADES"
    XaDES = "XADES"


class OpenOTPSoap(SOAP):
    """API SOAP class for OpenOTP endpoint."""

    def __init__(
        self,
        host: str,
        port: int = 8443,
        p12_file_path: str = None,
        p12_password: str = None,
        api_key: str = None,
        timeout: int = 30,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
        ca_file: str | None = None,
        vhost: str | None = None,
    ) -> None:
        """
        Construct OpenOTPSoap class.

        :param str host: path to the db file
        :param int port: listening port of OpenOTP server
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        :param str api_key: API key
        :param int timeout: timeout of connection
        :param ssl.VerifyMode verify_mode: one of ssl.CERT_NONE, ssl.CERT_OPTIONAL or ssl.CERT_REQUIRED. Default to
        ssl.CERT_REQUIRED
        :param str | None ca_file: path to the CA file for validating server certificate
        :param str | None vhost: virtual host that will be set as value for Host HTTP header
        """
        super().__init__(
            host,
            "openotp",
            port,
            p12_file_path,
            p12_password,
            api_key,
            timeout,
            verify_mode,
            ca_file,
            vhost
        )

    async def simple_login(
        self,
        username: str,
        domain: str = None,
        any_password: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        options: str = None,
        context: str = None,
        retry_id: str = None,
        virtual: str = None,
    ) -> dict:
        """
        Send a simple login request to the OpenOTP SOAP API.

        :param str username: username of account
        :param str domain: domain of account
        :param str any_password: password or OTP of account
        :param str client: client policy applied during authentication
        :param str source: IP source of authenticating client
        :param str settings: settings to apply during authentication
        :param str options: options to apply during authentication
        :param str context: context to apply during authentication
        :param str retry_id: retry ID of authentication
        :param str virtual: virtual settings to apply during authentication
        :return: a dictionary of the SOAP API response
        :rtype: str
        """
        params = {"username": username}
        if domain is not None:
            params["domain"] = domain
        if any_password is not None:
            params["anyPassword"] = any_password
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if options is not None:
            params["options"] = options
        if context is not None:
            params["context"] = context
        if retry_id is not None:
            params["retryId"] = retry_id
        if virtual is not None:
            params["virtual"] = virtual
        response = await super().handle_api_soap_request("SimpleLogin", params)
        return response

    async def normal_login(
        self,
        username: str,
        domain: str = None,
        ldap_password: str = None,
        otp_password: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        options: str = None,
        context: str = None,
        retry_id: str = None,
        virtual: str = None,
    ) -> dict:
        """
        Send a simple login request to the OpenOTP SOAP API.

        :param str username: username of account
        :param str domain: domain of account
        :param str ldap_password: LDAP password of account
        :param str otp_password: OTP password of account
        :param str client: client policy applied during authentication
        :param str source: IP source of authenticating client
        :param str settings: settings to apply during authentication
        :param str options: options to apply during authentication
        :param str context: context to apply during authentication
        :param str retry_id: retry ID of authentication
        :param str virtual: virtual settings to apply during authentication
        :return: a dictionary of the SOAP API response
        :rtype: str
        """
        params = {"username": username}
        if domain is not None:
            params["domain"] = domain
        if ldap_password is not None:
            params["ldapPassword"] = ldap_password
        if otp_password is not None:
            params["otpPassword"] = otp_password
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if options is not None:
            params["options"] = options
        if context is not None:
            params["context"] = context
        if retry_id is not None:
            params["retryId"] = retry_id
        if virtual is not None:
            params["virtual"] = virtual
        response = await super().handle_api_soap_request("NormalLogin", params)
        return response

    async def pki_login(
        self,
        certificate: str,
        client: str = None,
        source: str = None,
        settings: str = None,
        options: str = None,
        context: str = None,
        virtual: str = None,
    ) -> dict:
        """
        Send a simple login request to the OpenOTP SOAP API.

        :param str certificate: certificate
        :param str client: client policy applied during authentication
        :param str source: IP source of authenticating client
        :param str settings: settings to apply during authentication
        :param str options: options to apply during authentication
        :param str context: context to apply during authentication
        :param str virtual: virtual settings to apply during authentication
        :return: a dictionary of the SOAP API response
        :rtype: str
        """
        params = {"certificate": certificate}
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if options is not None:
            params["options"] = options
        if context is not None:
            params["context"] = context
        if virtual is not None:
            params["virtual"] = virtual
        response = await super().handle_api_soap_request("PKILogin", params)
        return response

    async def challenge(
        self,
        username: str,
        session: str,
        otp_password: str,
        domain: str = None,
    ) -> dict:
        """
        This method sends a response to a challenge request.

        :param str username: username of account
        :param str session: session of authentication
        :param str otp_password: OTP password of account
        :param str domain: domain of account
        :return: a dictionary of the SOAP API response
        :rtype: str
        """
        params = {"username": username, "session": session, "otpPassword": otp_password}
        if domain is not None:
            params["domain"] = domain
        response = await super().handle_api_soap_request("Challenge", params)
        return response

    async def normal_confirm(
        self,
        username: str,
        data: str,
        domain: str = None,
        async_: bool = None,
        timeout: int = None,
        issuer: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        virtual: str = None,
        file: str = None,
    ) -> dict:
        """
        This method sends a request for transactional confirmation (PSD2) or mobile signature (if a file is attached to
        the request).

        :param str username: username of account.
        :param str data: transaction.
        :param str domain: domain of account
        :param bool async_: boolean if confirmation or signature is asynchronous
        :param int timeout: timeout for confirmation or signature
        :param str issuer: Issuer of request
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :param str virtual: virtual settings to apply
        :param str file: file as base64 for signature
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "username": username,
            "data": data,
        }
        if domain is not None:
            params["domain"] = domain
        if async_ is not None:
            params["async"] = async_
        if timeout is not None:
            params["timeout"] = timeout
        if issuer is not None:
            params["issuer"] = issuer
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if virtual is not None:
            params["virtual"] = virtual
        if file is not None:
            if not re.compile(REGEX_BASE64).search(file):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING))
            params["file"] = file
        response = await super().handle_api_soap_request("NormalConfirm", params)
        return response

    async def confirm_qr_code(
        self,
        username: str,
        data: str,
        domain: str = None,
        timeout: int = None,
        issuer: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        qr_format: QRCodeFormat = None,
        qr_sizing: int = None,
        qr_margin: int = None,
        virtual: str = None,
        file: str = None,
    ) -> dict:
        """
        This method generates a QRCode for an associated transaction and is only available for corporate usage.
        The signature workflow will be initiated on YumiSign and the signatory will have the choice to receive the
        transaction/signature request by Push notification or by QRCode through YumiSign.

        :param str username: username of account.
        :param str data: transaction.
        :param str domain: domain of account
        :param int timeout: timeout for confirmation or signature
        :param str issuer: Issuer of request
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :param QRCodeFormat qr_format: format of QR code image
        :param int qr_sizing: size of QR code
        :param int qr_margin: marging of QR code
        :param str virtual: virtual settings to apply
        :param str file: file as base64 for signature
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "username": username,
            "data": data,
            "async": True,
        }
        if domain is not None:
            params["domain"] = domain
        if timeout is not None:
            params["timeout"] = timeout
        if issuer is not None:
            params["issuer"] = issuer
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if qr_format is not None:
            if not isinstance(qr_format, QRCodeFormat):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("qr_format", "QRCodeFormat"))
            params["qrFormat"] = qr_format.value
        if qr_sizing is not None:
            params["qrSizing"] = qr_sizing
        if qr_margin is not None:
            params["qrMargin"] = qr_margin
        if virtual is not None:
            params["virtual"] = virtual
        if file is not None:
            if not re.compile(REGEX_BASE64).search(file):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING))
            params["file"] = file
        response = await super().handle_api_soap_request("ConfirmQRCode", params)
        return response

    async def check_confirm(
        self,
        session: str,
    ) -> dict:
        """
        This method sends a check confirm request in order to get the status of any transactions. Request must include
        the session ID of corresponding transaction.

        :param str session: session id of transaction.
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "session": session,
        }
        response = await super().handle_api_soap_request("CheckConfirm", params)
        return response

    async def cancel_confirm(
        self,
        session: str,
    ) -> dict:
        """
        This method cancel a started transaction or mobile signature.

        :param str session: session id of transaction.
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "session": session,
        }
        response = await super().handle_api_soap_request("CancelConfirm", params)
        return response

    async def touch_confirm(
        self,
        session: str,
        send_push: bool = None,
        qr_format: QRCodeFormat = None,
        qr_sizing: int = None,
        qr_margin: int = None,
    ) -> dict:
        """
        This method can be used to re-send or convert (Push to QRCode or QRCode to Push) a request based on the session
        number.

        :param str session: session id of transaction.
        :param bool send_push: boolean if a PUSH is send to the mobile phone.
        :param QRCodeFormat qr_format: format of QR code image
        :param int qr_sizing: size of QR code
        :param int qr_margin: marging of QR code
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "session": session,
        }
        if send_push is not None:
            params["sendPush"] = send_push
        if qr_format is not None:
            if not isinstance(qr_format, QRCodeFormat):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("qr_format", "QRCodeFormat"))
            params["qrFormat"] = qr_format.value
        if qr_sizing is not None:
            params["qrSizing"] = qr_sizing
        if qr_margin is not None:
            params["qrMargin"] = qr_margin
        response = await super().handle_api_soap_request("TouchConfirm", params)
        return response

    async def normal_sign(
        self,
        username: str,
        data: str,
        domain: str = None,
        mode: SignatureMode = None,
        async_: bool = None,
        timeout: int = None,
        issuer: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        virtual: str = None,
        add_cert: bool = None,
        file: str = None,
    ) -> dict:
        """
        This method sends a request for advanced or qualified signature.

        The fact that an advanced signature or a qualified signature is requested is related to an OpenOTP SOAP
        setting named Signature Validity scope (SignScope). That setting is controllable by the client system
        sending the signature request to OpenOTP SOAP API or by client policy and can have 3 values:
        Local: Advanced signature with user certificates issued by internal WebADM CA. This should be used for internal
        signatories.
        Global: Advanced signature with user certificates issued by RCDevs
        Root CA. This should be used when external users are involved in a signature workflow with Yumisign.
        eIDAS: Qualified signature with external eIDAS signing devices (e.g. eID Cards).

        The SignScope must be passed in settings parameter of the SOAP request.

        :param str username: username of account.
        :param str data: transaction.
        :param str domain: domain of account
        :param SignatureMode mode: mode of signature
        :param bool async_: boolean if confirmation or signature is asynchronous
        :param int timeout: timeout for confirmation or signature
        :param str issuer: Issuer of request
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :param str virtual: virtual settings to apply
        :param bool add_cert: boolean if a certificate must be added
        :param str file: file as base64 for signature
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "username": username,
            "data": data,
        }
        if domain is not None:
            params["domain"] = domain
        if mode is not None:
            if not isinstance(mode, SignatureMode):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("mode", "SignatureMode"))
            params["mode"] = mode.value
        if async_ is not None:
            params["async"] = async_
        if timeout is not None:
            params["timeout"] = timeout
        if issuer is not None:
            params["issuer"] = issuer
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if virtual is not None:
            params["virtual"] = virtual
        if add_cert is not None:
            params["addCert"] = add_cert
        if file is not None:
            if not re.compile(REGEX_BASE64).search(file):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING))
            params["file"] = file
        response = await super().handle_api_soap_request("NormalSign", params)
        return response

    async def check_sign(
        self,
        session: str,
    ) -> dict:
        """
        This method sends a check sign request in order to get the status of an advanced or qualified signature.
        Request must include the session ID of corresponding signature.

        :param str session: session id of transaction.
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "session": session,
        }
        response = await super().handle_api_soap_request("CheckSign", params)
        return response

    async def cancel_sign(
        self,
        session: str,
    ) -> dict:
        """
        This method cancels a started signature.

        :param str session: session id of transaction.
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "session": session,
        }
        response = await super().handle_api_soap_request("CancelSign", params)
        return response

    async def touch_sign(
        self,
        session: str,
        send_push: bool = None,
        qr_format: QRCodeFormat = None,
        qr_sizing: int = None,
        qr_margin: int = None,
    ) -> dict:
        """
        This method can be used to re-send or convert (Push to QRCode or QRCode to Push) a request based on the session
        number.

        :param str session: session id of transaction.
        :param bool send_push: boolean if a PUSH is send to the mobile phone.
        :param QRCodeFormat qr_format: format of QR code image
        :param int qr_sizing: size of QR code
        :param int qr_margin: marging of QR code
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "session": session,
        }
        if send_push is not None:
            params["sendPush"] = send_push
        if qr_format is not None:
            if not isinstance(qr_format, QRCodeFormat):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("qr_format", "QRCodeFormat"))
            params["qrFormat"] = qr_format.value
        if qr_sizing is not None:
            params["qrSizing"] = qr_sizing
        if qr_margin is not None:
            params["qrMargin"] = qr_margin
        response = await super().handle_api_soap_request("TouchSign", params)
        return response

    async def sign_qr_code(
        self,
        username: str,
        data: str,
        domain: str = None,
        mode: SignatureMode = None,
        timeout: int = None,
        issuer: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        qr_format: QRCodeFormat = None,
        qr_sizing: int = None,
        qr_margin: int = None,
        virtual: str = None,
        add_cert: bool = None,
        file: str = None,
    ) -> dict:
        """
        This method generates a QRCode for an associated advanced or qualified signature.

        :param str username: username of account.
        :param str data: transaction.
        :param str domain: domain of account
        :param SignatureMode mode: mode of signature
        :param int timeout: timeout for qualified signature
        :param str issuer: Issuer of request
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :param QRCodeFormat qr_format: format of QR code image
        :param int qr_sizing: size of QR code
        :param int qr_margin: marging of QR code
        :param str virtual: virtual settings to apply
        :param bool add_cert: boolean if a certificate must be added
        :param str file: file as base64 for signature
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "username": username,
            "data": data,
            "async": True,
        }
        if domain is not None:
            params["domain"] = domain
        if mode is not None:
            if not isinstance(mode, SignatureMode):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("mode", "SignatureMode"))
            params["mode"] = mode.value
        if timeout is not None:
            params["timeout"] = timeout
        if issuer is not None:
            params["issuer"] = issuer
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if qr_format is not None:
            if not isinstance(qr_format, QRCodeFormat):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("qr_format", "QRCodeFormat"))
            params["qrFormat"] = qr_format.value
        if qr_sizing is not None:
            params["qrSizing"] = qr_sizing
        if qr_margin is not None:
            params["qrMargin"] = qr_margin
        if virtual is not None:
            params["virtual"] = virtual
        if add_cert is not None:
            params["addCert"] = add_cert
        if file is not None:
            if not re.compile(REGEX_BASE64).search(file):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING))
            params["file"] = file
        response = await super().handle_api_soap_request("SignQRCode", params)
        return response

    async def list(self) -> dict:
        """
        This method sends a request for getting a list of pending and recently finished transactions or signatures.

        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        response = await super().handle_api_soap_request("List", {})
        return response

    async def seal(
        self,
        file: str,
        mode: SignatureMode = None,
        client: str = None,
        source: str = None,
        settings: str = None,
    ) -> dict:
        """
        This method sends a request for sealing a document.

        :param str file: file as base64 for signature
        :param SignatureMode mode: file as base64 for signature
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        if not re.compile(REGEX_BASE64).search(file):
            raise TypeError(MSG_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING))
        params = {
            "file": file,
        }
        if mode is not None:
            if not isinstance(mode, SignatureMode):
                raise TypeError(MSG_NOT_RIGHT_TYPE.format("mode", "SignatureMode"))
            params["mode"] = mode.value
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        response = await super().handle_api_soap_request("Seal", params)
        return response

    async def start_badging(
        self,
        username: str,
        data: str,
        domain: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
        virtual: str = None,
    ) -> dict:
        """
        This method sends a request for badging (Badge mode) for a specific username.

        :param str username: username of account.
        :param str data: transaction.
        :param str domain: domain of account
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :param str virtual: virtual settings to apply
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "username": username,
            "data": data,
        }
        if domain is not None:
            params["domain"] = domain
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        if virtual is not None:
            params["virtual"] = virtual
        response = await super().handle_api_soap_request("StartBadging", params)
        return response

    async def check_badging(
        self,
        username: str,
        domain: str = None,
        office: bool = None,
        client: str = None,
        source: str = None,
        settings: str = None,
    ) -> dict:
        """
        This method sends a request for badging (Check mode) for a specific username.

        :param str username: username of account.
        :param str domain: domain of account
        :param bool office: office
        :param str client: client policy
        :param str source: source IP
        :param str settings: settings to apply
        :return: a dictionary of the SOAP API response
        :rtype: dict
        """
        params = {
            "username": username,
        }
        if domain is not None:
            params["domain"] = domain
        if office is not None:
            params["office"] = office
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        response = await super().handle_api_soap_request("CheckBadging", params)
        return response
