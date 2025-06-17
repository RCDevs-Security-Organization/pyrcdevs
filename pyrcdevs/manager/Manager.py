"""This module implements parent class for Manager APIs (OpenOTP, PwReset, SelfReg, SpanKey, WebADM)."""

import json
import ssl
import tempfile
from typing import Any

import aiohttp
from aiohttp import BasicAuth
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12


def create_request_data(method_name, params) -> json:
    """
    Create the JSON request using method name and parameters.

    :param str method_name: name of called method.
    :param dict params: dictionnary of method parameters.
    :return: JSON request
    :rtype: json
    """
    return {"jsonrpc": "2.0", "method": method_name, "params": params, "id": 0}


class InvalidAPICredentials(Exception):
    """Raised when authentication fails."""

    pass


class InvalidJSONContent(Exception):
    """Raised when json response has not right format."""

    pass


class InvalidParams(Exception):
    """Raised when json response has not right format."""

    pass


class InternalError(Exception):
    """Raised when json response has not right format."""

    pass


class ServerError(Exception):
    """Raised when json response has not right format."""

    pass


class UnknownError(Exception):
    """Raised when json response has not right format."""

    pass


class Manager:
    """
    API Manager class.

    ...

    Attributes
    ----------
    host: str hostname or IP of WebADM server
    port: str listening port of WebADM server
    username: str username for API authentication
    password: str password for API authentication
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        p12_file_path: str,
        p12_password: str,
        timeout: int,
        port: int = 443,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
        ca_file: str | None = None,
        vhost: str | None = None,
    ) -> None:
        """
        Construct Manager class.

        :param str host: path to the db file
        :param str username: username for API authentication
        :param str password: password for API authentication
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        :param int port: listening port of WebADM server
        :param ssl.VerifyMode verify_mode: one of ssl.CERT_NONE, ssl.CERT_OPTIONAL or ssl.CERT_REQUIRED. Default to
        ssl.CERT_REQUIRED
        :param str | None ca_file: path to the CA file for validating server certificate
        :param str | None vhost: virtual host that will be set as value for Host HTTP header
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_mode = verify_mode
        self.ca_file = ca_file
        self.vhost = vhost
        self.timeout = timeout
        if None not in [p12_file_path, p12_password]:
            self.p12_file_path = p12_file_path
            self.p12_password = p12_password
            self.client_auth = True
        else:
            self.p12_file_path = None
            self.p12_password = None
            self.client_auth = False

        self.ssl_context = None

    async def handle_api_manager_request(self, method_name, params) -> Any:
        """
        Handle request to manag API endpoint.

        This creates data request, make request to the manag API endpoint, then check response before returning it.

        :param str method_name: method name
        :param dict params: dictionnary of method parameters
        :return: response of API
        :rtype: Any
        """
        request_data = create_request_data(method_name, params)

        if self.ssl_context is None:
            self.ssl_context = await self.create_ssl_context()

        headers = {"Content-Type": "application/json"}
        if self.vhost is not None:
            headers["Host"] = self.vhost

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{self.host}:{self.port}/manag/",
                ssl=self.ssl_context,
                json=request_data,
                headers=headers,
                auth=BasicAuth(self.username, self.password),
            ) as response:
                # Ensure the response is JSON
                response.raise_for_status()
                json_reponse = await response.json()

        json_reponse_keys = json_reponse.keys()

        if "result" not in json_reponse_keys and "error" not in json_reponse_keys:
            raise InvalidJSONContent(str(json_reponse))

        if "error" in json_reponse_keys:
            if "code" in json_reponse.get("error").keys():
                code = json_reponse.get("error").get("code")
                if code == -32600:
                    raise InvalidAPICredentials("Invalid username or password")
                elif code == -32603:
                    raise InternalError(json_reponse.get("error").get("data"))
                elif code == -32602:
                    raise InvalidParams(json_reponse.get("error").get("data"))
                elif code == -32000:
                    raise ServerError(json_reponse.get("error").get("data"))
            else:
                raise UnknownError(json_reponse.get("error"))

        return json_reponse.get("result")

    async def create_ssl_context(self) -> ssl.SSLContext:
        """
        Create an SSL context. This will load client certificate if p12 file and password are provided during
        object instanciation.

        :return: SSL context for use with aiohttp.
        """
        if self.client_auth:
            # Load the .p12 file
            with open(self.p12_file_path, "rb") as f:
                p12_data = f.read()

            # Decode the .p12 file
            private_key, certificate, _ = pkcs12.load_key_and_certificates(
                p12_data, self.p12_password.encode("utf-8"), default_backend()
            )
            cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(self.p12_password.encode())
            )

            # Create an SSL context
            ssl_context = ssl.create_default_context()  # NOSONAR
            ssl_context.load_verify_locations(cafile=self.ca_file)

            # Create a temporary files for certificate and key
            cert_path = tempfile.NamedTemporaryFile()
            key_path = tempfile.NamedTemporaryFile()

            # Write the certificate and key to temporary files
            with open(cert_path.name, 'wb') as cert_file:
                cert_file.write(cert_pem)

            with open(key_path.name, 'wb') as key_file:
                key_file.write(key_pem)

            ssl_context.load_cert_chain(
                certfile=cert_path.name,
                keyfile=key_path.name,
                password=lambda: self.p12_password.encode('utf-8'),
            )
        else:
            ssl_context = ssl.create_default_context(cafile=self.ca_file)  # NOSONAR
        ssl_context.check_hostname = (self.verify_mode != ssl.CERT_NONE)
        ssl_context.verify_mode = self.verify_mode
        return ssl_context
