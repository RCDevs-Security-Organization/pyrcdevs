"""This module implements OpenOTP SOAP API."""

import ssl
from enum import Enum

from pyrcdevs.soap.SOAP import SOAP


class SMSType(Enum):
    """Enum for SMS types."""

    NORMAL = "Normal"
    FLASH = "Flash"


class SMSHubSoap(SOAP):
    """API SOAP class for SMSHub endpoint."""

    def __init__(
        self,
        host: str,
        port: int,
        p12_file_path: str = None,
        p12_password: str = None,
        api_key: str = None,
        timeout: int = 30,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
        ca_file: str | None = None,
        vhost: str | None = None,
    ) -> None:
        """
        Construct SMSHubSoap class.

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
            "smshub",
            port,
            p12_file_path,
            p12_password,
            api_key,
            timeout,
            verify_mode,
            ca_file,
            vhost
        )

    async def send(
        self,
        username: str,
        password: str,
        mobile: list,
        text: str = None,
        type_: SMSType = None,
        sender: str = None,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method sends an SMS to a specific mobile phone number.

        :param str username: username of static account configured in SMSHub server.
        :param str password: password of static account configured in SMSHub server.
        :param list mobile: list of mobile phone numbers
        :param str text: text of SMS
        :param SMSType type_: type of SMS
        :param str sender: sender of SMS
        :param str client: client policy
        :param str source: source IP
        :return: a dictionary including information on password update
        :rtype: dict
        """
        params = {
            "username": username,
            "password": password,
            "mobile": mobile,
            "text": text,
        }
        if type_ is not None:
            if not isinstance(type_, SMSType):
                raise TypeError("type_ is not SMSType")
            params["type"] = type_.value
        if sender is not None:
            params["sender"] = sender
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("Send", params)
        return response

    async def sign(
        self,
        username: str,
        password: str,
        mobile: list,
        text: str = None,
        timeout: int = None,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method sends a signature SMS to a specific mobile phone number.

        :param str username: username of static account configured in SMSHub server.
        :param str password: password of static account configured in SMSHub server.
        :param list mobile: list of mobile phone numbers
        :param str text: text of SMS
        :param int timeout: timeout for signature
        :param str client: client policy
        :param str source: source IP
        :return: a dictionary including information on password update
        :rtype: dict
        """
        params = {
            "username": username,
            "password": password,
            "mobile": mobile,
            "text": text,
        }
        if timeout is not None:
            params["timeout"] = timeout
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("Sign", params)
        return response
