"""This module implements parent class for SOAP APIs (OpenOTP, SpanKey, SMSHub)."""
import ssl
import tempfile
import xml.parsers.expat
from typing import Any

import aiohttp
import xmltodict
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from pyrcdevs.constants import XML_SOAP_BODY, XML_SOAP_ENVELOP


class InvalidAPICredentials(Exception):
    """Raised when authentication fails."""

    pass


class InvalidSOAPContent(Exception):
    """Raised when soap response has not right format."""

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


class SOAP:
    """
    SOAP API class.

    ...

    Attributes
    ----------
    host: str hostname or IP of WebADM server
    port: str listening port of WebADM server
    """

    def __init__(
        self,
        host: str,
        service: str,
        port: int = 8443,
        p12_file_path: str = None,
        p12_password: str = None,
        api_key: str = None,
        timeout: int = 10,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
        ca_file: str | None = None,
        vhost: str | None = None,
    ) -> None:
        """
        Construct Manager class.

        :param str host: path to the db file
        :param str service: endpoint
        :param int port: listening port of WebADM server (Default to 8443)
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        :param str api_key: API key
        :param int timeout: timeout of connection
        :param ssl.VerifyMode verify_mode: one of ssl.CERT_NONE, ssl.CERT_OPTIONAL or ssl.CERT_REQUIRED. Default to
        ssl.CERT_REQUIRED
        :param str | None ca_file: path to the CA file for validating server certificate
        :param str | None vhost: virtual host that will be set as value for Host HTTP header
        """
        self.host = host
        self.verify_mode = verify_mode
        self.ca_file = ca_file
        self.service = service.lower()
        self.port = port
        self.timeout = timeout
        self.vhost = vhost
        if (
            p12_file_path is not None or p12_password is not None
        ) and api_key is not None:
            raise InvalidParams(
                "Client certificate and API key cannot be used together!"
            )
        if None not in [p12_file_path, p12_password]:
            self.p12_file_path = p12_file_path
            self.p12_password = p12_password
            self.client_auth = True
        else:
            self.p12_file_path = None
            self.p12_password = None
            self.client_auth = False

        self.ssl_context = None

        self.api_key = api_key

    async def handle_api_soap_request(self, method_name, params) -> Any:
        """
        Handle request to SOAP API endpoint.

        This creates data request, make request to the SOAP API endpoint, then check response before returning it.

        :param str method_name: method name
        :param dict params: dictionnary of method parameters
        :return: response of API
        :rtype: Any
        """
        request_data = self.create_request_data(method_name, params)
        headers = {"Content-Type": "application/xml"}
        if self.api_key and not self.client_auth:
            headers["WA-API-Key"] = self.api_key

        if self.vhost is not None:
            headers["Host"] = self.vhost

        if self.ssl_context is None:
            self.ssl_context = await self.create_ssl_context()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"https://{self.host}:{self.port}/{self.service}/",
                ssl=self.ssl_context,
                data=request_data,
                headers=headers,
                timeout=self.timeout,
            ) as response:
                if response.status == 401:
                    raise InvalidAPICredentials(
                        "Invalid client certificate" if self.client_auth else "Invalid API key"
                    )

                content = await response.text()

            try:
                soap_reponse = xmltodict.parse(content)
            except xml.parsers.expat.ExpatError:
                raise InvalidSOAPContent(str(response.text))

            if (
                XML_SOAP_ENVELOP not in soap_reponse
                or XML_SOAP_BODY not in soap_reponse[XML_SOAP_ENVELOP]
                or f"ns1:{self.service}{method_name}Response"
                not in soap_reponse[XML_SOAP_ENVELOP][XML_SOAP_BODY]
                or (
                    not all(
                        prefix
                        in soap_reponse[XML_SOAP_ENVELOP][XML_SOAP_BODY][
                            f"ns1:{self.service}{method_name}Response"
                        ]
                        for prefix in ("code", "message")
                    )
                    and not all(
                        prefix
                        in soap_reponse[XML_SOAP_ENVELOP][XML_SOAP_BODY][
                            f"ns1:{self.service}{method_name}Response"
                        ]
                        for prefix in ("status", "message")
                    )
                )
            ):
                raise InvalidSOAPContent(str(soap_reponse))

            return soap_reponse[XML_SOAP_ENVELOP][XML_SOAP_BODY][
                f"ns1:{self.service}{method_name}Response"
            ]

    def create_request_data(self, method_name, params) -> str:
        """
        Create the SOAP request using method name and parameters.

        :param str method_name: name of called method.
        :param dict params: dictionnary of method parameters.
        :return: request as a string
        :rtype: str
        """

        params_xml = ""
        for k, v in params.items():
            if isinstance(v, list):
                params_xml += f"<{k}>"
                for sub_elm in v:
                    params_xml += f"<String>{sub_elm}</String>"
                params_xml += f"</{k}>"
            else:
                params_xml += f"<{k}>{v}</{k}>"

        return (
            f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:urn="urn:{self.service}">'
            "<soapenv:Header/>"
            "<soapenv:Body>"
            f"<urn:{self.service}{method_name}>{params_xml}</urn:{self.service}{method_name}>"
            "</soapenv:Body>"
            "</soapenv:Envelope>"
        )

    async def status(self) -> dict:
        """
        Get status information of service endpoint.

        :return: a dictionary of endpoint status
        :rtype: dict
        """
        response = await self.handle_api_soap_request("Status", {})
        return response

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
