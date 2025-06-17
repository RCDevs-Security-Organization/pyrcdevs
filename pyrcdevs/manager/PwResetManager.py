"""This module implements PwReset API Manager."""
import ssl
from enum import Enum
from typing import Any

from pyrcdevs.manager.Manager import Manager


class MethodType(Enum):
    """Enum for sending method types."""

    MAIL = "MAIL"
    SMS = "SMS"
    MAILSMS = "MAILSMS"
    NONE = "NONE"


class PwResetManager(Manager):
    """API manag class for PwReset endpoint."""

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
        Construct PwReset class.

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
            vhost
        )

    async def send_request(
        self, username, domain=None, method=None, expires=None, mfa=None, comments=None
    ) -> Any:
        """
        Send a password reset link to the specified user.

        :param str username: username of account.
        :param str domain: domain is required if no default domain is set.
        :param MethodType method: how PwReset link is sent (see MethodType for possible values)
        :param int expires: validity of PwReset link (between 1 and 720, in hours)
        :param bool mfa: if True, then a second factor (OpenOTP/PKI) is required.
        :param str comments: if specified, then it is added to the email message template.
        :return: HTTP link on success and false on error.
        :rtype: Any
        """
        if method is not None and not isinstance(method, MethodType):
            raise TypeError("method type is not MethodType")
        if expires is not None and not (1 <= expires <= 720):
            raise ValueError("expires value must be between 1 and 720!")
        params = {"username": username}
        if domain is not None:
            params["domain"] = domain
        if method is not None:
            params["method"] = method.value
        if expires is not None:
            params["expires"] = expires
        if mfa is not None:
            params["mfa"] = mfa
        if comments is not None:
            params["comments"] = comments
        response = await super().handle_api_manager_request(
            "PwReset.Send_Request", params
        )
        return response
