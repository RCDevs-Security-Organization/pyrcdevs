"""This module implements SpanKey API Manager."""
import ssl
from enum import Enum
from typing import Any

from pyrcdevs.constants import MSG_EXPIRES_POSSIBLE_VALUES, MSG_MAXUSE_POSSIBLE_VALUES
from pyrcdevs.manager.Manager import Manager


class KeyType(Enum):
    """Enum for cryptographic key type."""

    RSA = "RSA"
    ECC = "ECC"
    DSA = "DSA"


class KeySize(Enum):
    """Enum for cryptographic key size."""

    RSA_DSA_1024 = 1024
    RSA_DSA_2048 = 2048
    RSA_DSA_4096 = 4096
    ECC_256 = 256
    ECC_384 = 384
    ECC_521 = 521


class KeyExportFormat(Enum):
    """Enum for key export format."""

    PEM = "PEM"
    PPK = "PPK"


class SpanKeyManager(Manager):
    """API manag class for SpanKey endpoint."""

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
        Construct SpanKey class.

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

    async def key_register(self, dn, type_, size=None, expires=None, maxuse=None) -> Any:
        """
        Generate a SSH key pair and registers the public key on the user account.

        :param str dn: distinghuished name of user account.
        :param KeyType type_: type of cryptographic key (see KeyType for possible values).
        :param KeySize size: size of cryptographic key (see Keysize for possible values).
        :param int expires: validity of key (between 0 (never expire) and 360, in days)
        :param int maxuse: maximum number of time key can be used (between 0 (no limitation) and 500)
        :return: private key on success and false on error.
        :rtype: Any
        """
        if not isinstance(type_, KeyType):
            raise TypeError("type_ is not of KeyType type")
        if size is not None and not isinstance(size, KeySize):
            raise TypeError("size type is not KeySize!")
        if expires is not None and not (0 <= expires <= 360):
            raise ValueError(MSG_EXPIRES_POSSIBLE_VALUES)
        if maxuse is not None and not (0 <= maxuse <= 500):
            raise ValueError(MSG_MAXUSE_POSSIBLE_VALUES)
        params = {"dn": dn, "type": type_.value}
        if size is not None:
            params["size"] = size.value
        if expires is not None:
            params["expires"] = expires
        if maxuse is not None:
            params["maxuse"] = maxuse
        response = await super().handle_api_manager_request(
            "SpanKey.Key_Register", params
        )
        return response

    async def fido_challenge(self, username, domain, random, appid=None) -> Any:
        """
        Return a JSON-encoded FIDO registration challenge.

        :param str username: username of account
        :param str domain: domain where user account belongs to.
        :param str random: random string
        :param str appid: FIDO appid
        :return: JSON-encoded FIDO registration challenge.
        :rtype: Any
        """
        params = {"username": username, "domain": domain, "random": random}
        if appid is not None:
            params["appid"] = appid
        response = await super().handle_api_manager_request(
            "SpanKey.FIDO_Challenge", params
        )
        return response

    async def fido_register(self, dn, response, random) -> bool:
        """
        Register a FIDO device.

        :param str dn: distinguished name of account
        :param str response: output from the U2F device.
        :param str random: random string
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "response": response, "random": random}
        response = await super().handle_api_manager_request(
            "SpanKey.FIDO_Register", params
        )
        return response

    async def key_export(self, privkey, format_=None, password=None) -> Any:
        """
        Export the generated PEM-encoded private key for use with OpenSSH or PuTTY.

        :param str privkey: private key in PEM format.
        :param KeyExportFormat format_: output format for key (see KeyExportFormat for possible values)
        :param str password: maximum number of time key can be used (between 0 (no limitation) and 500)
        :return: formatted private key on success and false on error.
        :rtype: Any
        """
        if format_ is not None and not isinstance(format_, KeyExportFormat):
            raise TypeError("format type is not KeyExportFormat!")
        params = {"privkey": privkey}
        if format_ is not None:
            params["format"] = format_.value
        if password is not None:
            params["password"] = password
        response = await super().handle_api_manager_request(
            "SpanKey.Key_Export", params
        )
        return response

    async def key_import(self, dn, pubkey, expires=None, maxuse=None) -> bool:
        """
        Import RSA public keys.

        Key can be in SSH or PEM format.

        :param str dn: distinghuished name of user account.
        :param str pubkey: public key in SSH or PEM format
        :param int expires: validity of key (between 0 (never expire) and 360, in days)
        :param int maxuse: maximum number of time key can be used (between 0 (no limitation) and 500)
        :return:  true on success and false on error.
        :rtype: bool
        """
        if expires is not None and not (0 <= expires <= 360):
            raise ValueError(MSG_EXPIRES_POSSIBLE_VALUES)
        if maxuse is not None and not (0 <= maxuse <= 500):
            raise ValueError(MSG_MAXUSE_POSSIBLE_VALUES)
        params = {"dn": dn, "pubkey": pubkey}
        if expires is not None:
            params["expires"] = expires
        if maxuse is not None:
            params["maxuse"] = maxuse
        response = await super().handle_api_manager_request(
            "SpanKey.Key_Import", params
        )
        return response

    async def key_restrict(self, dn, expires=None, maxuse=None) -> bool:
        """
        Change or remove the expiration or max use for the registered public key.

        :param str dn: distinghuished name of user account.
        :param int expires: validity of key (between 0 (never expire) and 360, in days)
        :param int maxuse: maximum number of time key can be used (between 0 (no limitation) and 500)
        :return:  true on success and false on error.
        :rtype: bool
        """
        if expires is not None and not (0 <= expires <= 360):
            raise ValueError(MSG_EXPIRES_POSSIBLE_VALUES)
        if maxuse is not None and not (0 <= maxuse <= 500):
            raise ValueError(MSG_MAXUSE_POSSIBLE_VALUES)
        params = {"dn": dn}
        if expires is not None:
            params["expires"] = expires
        if maxuse is not None:
            params["maxuse"] = maxuse
        response = await super().handle_api_manager_request(
            "SpanKey.Key_Restrict", params
        )
        return response

    async def key_unregister(self, dn) -> bool:
        """
        Unregister a public key from user account.

        :param str dn: distinghuished name of user account.
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn}
        response = await super().handle_api_manager_request(
            "SpanKey.Key_Unregister", params
        )
        return response

    async def piv_register(self, dn, serial) -> bool:
        """
        Register an inventoried PIV public key on the user account.

        :param str dn: distinghuished name of user account.
        :param str serial: serial number of key to be imported
        :return: true on success and false on error.
        :rtype: bool
        """
        params = {"dn": dn, "serial": serial}
        response = await super().handle_api_manager_request(
            "SpanKey.PIV_Register", params
        )
        return response
