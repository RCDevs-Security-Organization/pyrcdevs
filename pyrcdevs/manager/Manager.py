"""This module implements parent class for Manager APIs (OpenOTP, PwReset, SelfReg, SpanKey, WebADM)."""

import json
from typing import Any

import requests
import requests_pkcs12


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
        host,
        port,
        username,
        password,
        verify,
        p12_file_path,
        p12_password,
        timeout,
    ) -> None:
        """
        Construct Manager class.

        :param str host: path to the db file
        :param str port: listening port of WebADM server
        :param str username: username for API authentication
        :param str password: password for API authentication
        :param bool|str verify: Either boolean (verify or not TLS certificate), or path (str) to
        CA certificate
        :param str p12_file_path: path to pkcs12 file used when TLS client auth is required
        :param str p12_password: password of pkcs12 file
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify = verify
        self.timeout = timeout
        if None not in [p12_file_path, p12_password]:
            self.p12_file_path = p12_file_path
            self.p12_password = p12_password
            self.client_auth = True
        else:
            self.p12_file_path = None
            self.p12_password = None
            self.client_auth = False

        self.handle_api_manager_request("Server_Status", {})

    def handle_api_manager_request(self, method_name, params) -> Any:
        """
        Handle request to manag API endpoint.

        This creates data request, make request to the manag API endpoint, then check response before returning it.

        :param str method_name: method name
        :param dict params: dictionnary of method parameters
        :return: response of API
        :rtype: Any
        """
        request_data = create_request_data(method_name, params)
        if self.client_auth:
            response = requests_pkcs12.post(
                f"https://{self.host}:{self.port}/manag/",
                auth=(self.username, self.password),
                json=request_data,
                verify=self.verify,
                pkcs12_filename=self.p12_file_path,
                pkcs12_password=self.p12_password,
                timeout=self.timeout,
            )
        else:
            response = requests.post(
                f"https://{self.host}:{self.port}/manag/",
                auth=(self.username, self.password),
                json=request_data,
                verify=self.verify,
                timeout=self.timeout,
            )
        json_reponse = response.json()

        json_reponse_keys = json_reponse.keys()

        if "result" not in json_reponse_keys and "error" not in json_reponse_keys:
            raise InvalidJSONContent(str(json_reponse))

        if "error" in json_reponse_keys:
            if "code" in json_reponse.get("error").keys():
                code = json_reponse.get("error").get("code")
                if code == -32600:
                    raise InvalidAPICredentials
                elif code == -32603:
                    raise InternalError(json_reponse.get("error").get("data"))
                elif code == -32602:
                    raise InvalidParams(json_reponse.get("error").get("data"))
                elif code == -32000:
                    raise ServerError(json_reponse.get("error").get("data"))
            else:
                raise UnknownError(json_reponse.get("error"))

        return json_reponse.get("result")
