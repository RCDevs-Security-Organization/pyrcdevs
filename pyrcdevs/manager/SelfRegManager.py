"""This module implements SelfReg API Manager."""

from enum import Enum
from typing import Any

from pyrcdevs.manager.Manager import Manager


class MethodType(Enum):
    """Enum for sending method type."""

    MAIL = "MAIL"
    SMS = "SMS"
    MAILSMS = "MAILSMS"
    NONE = "NONE"


class Application(Enum):
    """Enum for type of applications."""

    OPENOTP = "OpenOTP"
    SPANKEY = "SpanKey"
    PKI = "PKI"


class Item(Enum):
    """Enum for type of items."""

    TOKEN1 = "Token1"
    TOKEN2 = "Token2"
    TOKEN3 = "Token3"
    FIDO = "FIDO"
    OTPLIST = "OTPList"
    APPKEYS = "AppKeys"
    VOICE = "Voice"


class SelfRegManager(Manager):
    """API manag class for SelfReg endpoint."""

    def __init__(
        self,
        host,
        port,
        username,
        password,
        verify=True,
        p12_file_path=None,
        p12_password=None,
        timeout=30,
    ) -> None:
        """
        Construct SelfReg class.

        :param str host: path to the db file
        :param str port: listening port of WebADM server
        :param str username: username for API authentication
        :param str password: password for API authentication
        :param bool|str verify: Either boolean (verify or not TLS certificate), or path (str) to
        CA certificate
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        """
        super().__init__(
            host, port, username, password, verify, p12_file_path, p12_password, timeout
        )

    def send_request(
        self,
        username,
        domain=None,
        method=None,
        application=None,
        item=None,
        expires=None,
        comments=None,
    ) -> Any:
        """
        Send a password reset link to the specified user.

        :param str username: username of account.
        :param str domain: domain is required if no default domain is set.
        :param MethodType method: how SelfReg link is sent (see MethodType for possible values)
        :param Application application: application to which link will apply (see Application for possible values)
        :param Item item:  The item indicates which item is to be registered (see Item for possible values)
        :param int expires: validity of SelfReg link (between 300 and 604800, in seconds)
        :param str comments: if specified, then it is added to the email message template.
        :return: HTTP link on success and false on error.
        :rtype: Any
        """
        if method is not None and not isinstance(method, MethodType):
            raise TypeError("method type is not MethodType")
        if application is not None and not isinstance(application, Application):
            raise TypeError("appliction type is not Application")
        if item is not None and not isinstance(item, Item):
            raise TypeError("item type is not Item")
        if expires is not None and not (300 <= expires <= 604800):
            raise ValueError("expires value must be between 300 and 604800!")
        params = {"username": username}
        if domain is not None:
            params["domain"] = domain
        if method is not None:
            params["method"] = method.value
        if application is not None:
            params["application"] = application.value
        if item is not None:
            params["item"] = item.value
        if expires is not None:
            params["expires"] = expires
        if comments is not None:
            params["comments"] = comments
        response = super().handle_api_manager_request("SelfReg.Send_Request", params)
        return response
