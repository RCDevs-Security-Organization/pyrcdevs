"""This module implements parent class for SOAP APIs (OpenOTP, SpanKey, SMSHub)."""

import xml.parsers.expat
from typing import Any

import requests
import requests_pkcs12
import xmltodict

MSG_SOAP_BODY = "SOAP-ENV:Body"

MSG_SOAP_ENVELOP = "SOAP-ENV:Envelope"


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
        host,
        port,
        verify,
        service,
        p12_file_path=None,
        p12_password=None,
        api_key=None,
        timeout=10,
    ) -> None:
        """
        Construct Manager class.

        :param str host: path to the db file
        :param str port: listening port of WebADM server
        :param bool|str verify: Either boolean (verify or not TLS certificate), or path (str) to
        CA certificate
        :param str service: endpoint
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        :param str api_key: API key
        :param int timeout: timeout of connection
        """
        self.host = host
        self.port = port
        self.verify = verify
        self.service = service.lower()
        self.timeout = timeout
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

        self.api_key = api_key

    def handle_api_soap_request(self, method_name, params) -> Any:
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

        if self.client_auth:
            response = requests_pkcs12.post(
                f"https://{self.host}:{self.port}/{self.service}/",
                data=request_data,
                verify=self.verify,
                pkcs12_filename=self.p12_file_path,
                pkcs12_password=self.p12_password,
                timeout=self.timeout,
                headers=headers,
            )
        else:
            response = requests.post(
                f"https://{self.host}:{self.port}/{self.service}/",
                data=request_data,
                verify=self.verify,
                timeout=self.timeout,
                headers=headers,
            )

        if response.status_code == 401:
            raise InvalidAPICredentials("Invalid client certificate" if self.client_auth else "Invalid API key")

        try:
            soap_reponse = xmltodict.parse(response.content)
        except xml.parsers.expat.ExpatError:
            raise InvalidSOAPContent(str(response.text))

        if (
            MSG_SOAP_ENVELOP not in soap_reponse
            or MSG_SOAP_BODY not in soap_reponse[MSG_SOAP_ENVELOP]
            or f"ns1:{self.service}{method_name}Response"
            not in soap_reponse[MSG_SOAP_ENVELOP][MSG_SOAP_BODY]
            or (
                not all(
                    prefix
                    in soap_reponse[MSG_SOAP_ENVELOP][MSG_SOAP_BODY][
                        f"ns1:{self.service}{method_name}Response"
                    ]
                    for prefix in ("code", "message")
                )
                and not all(
                    prefix
                    in soap_reponse[MSG_SOAP_ENVELOP][MSG_SOAP_BODY][
                        f"ns1:{self.service}{method_name}Response"
                    ]
                    for prefix in ("status", "message")
                )
            )
        ):
            raise InvalidSOAPContent(str(soap_reponse))

        return soap_reponse[MSG_SOAP_ENVELOP][MSG_SOAP_BODY][
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

    def status(self) -> dict:
        """
        Get status information of service endpoint.

        :return: a dictionary of endpoint status
        :rtype: dict
        """
        response = self.handle_api_soap_request("Status", {})
        return response
