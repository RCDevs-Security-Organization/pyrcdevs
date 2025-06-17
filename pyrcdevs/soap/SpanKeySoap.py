"""This module implements SpanKey SOAP API."""

import re
import ssl
from enum import Enum

from pyrcdevs.constants import KEY_NS2_MAP, REGEX_BASE64
from pyrcdevs.soap.SOAP import SOAP


def reconstruct_nss_data(response):
    if KEY_NS2_MAP in response["data"]:
        objects = response["data"][KEY_NS2_MAP]
    else:
        objects = response["data"]
    new_data = {}
    if not isinstance(objects, list):
        objects = [objects]
    for object_ in objects:
        if "item" in object_ and isinstance(object_["item"], list):
            new_object = {o["key"]: o["value"] for o in object_["item"]}
            if "name" in new_object:
                name = new_object["name"]
                new_object.pop("name")
                new_data[name] = new_object
                response["data"] = new_data


class NSSDatabaseType(Enum):
    """Enum for NSS database types."""

    USER = "user"
    GROUP = "group"


class SpanKeySoap(SOAP):
    """API SOAP class for SpanKey endpoint."""

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
        Construct SpanKeySoap class.

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
            "spankey",
            port,
            p12_file_path,
            p12_password,
            api_key,
            timeout,
            verify_mode,
            ca_file,
            vhost
        )

    async def nss_list(
        self,
        database: NSSDatabaseType,
        domain: str = None,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method lists all users or groups configured for SpanKey.

        :param NSSDatabaseType database:
        :param str domain: domain of user account
        :param str client: client policy
        :param str source: source IP
        :return: a dictionary with information on SSH users or groups
        :rtype: dict
        """
        if not isinstance(database, NSSDatabaseType):
            raise TypeError("database type is not NSSDatabaseType")
        params = {"database": database.value}
        if domain is not None:
            params["domain"] = domain
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("NSSList", params)

        if (
            "data" not in response
            or not response["data"]
            or KEY_NS2_MAP not in response["data"]
        ):
            response["data"] = {}
        else:
            reconstruct_nss_data(response)
        return response

    async def nss_info(
        self,
        database: NSSDatabaseType,
        domain: str = None,
        name: str = None,
        id_: int = None,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method provide information on a specific user or group configured for SpanKey.

        :param NSSDatabaseType database:
        :param str domain: domain of user account
        :param id_: uidnumber of user or group
        :param name: name of user or group
        :param str client: client policy
        :param str source: source IP
        :return: a dictionnary with information on user or group
        :rtype: dict
        """
        if not isinstance(database, NSSDatabaseType):
            raise TypeError("database type is not NSSDatabaseType")
        params = {"database": database.value}
        if domain is not None:
            params["domain"] = domain
        if name is not None:
            params["name"] = name
        if id_ is not None:
            params["id"] = id_
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("NSSInfo", params)
        if "data" not in response or not response["data"]:
            return response

        reconstruct_nss_data(response)
        return response

    async def authorized_keys(
        self,
        username: str,
        domain: str = None,
        client: str = None,
        source: str = None,
        settings: str = None,
    ) -> dict:
        """
        This method returns SSH key enrolled on a specific username.

        :param str username: username of account.
        :param str domain: domain of user account
        :param str client: client policy
        :param str source: source IP
        :param str settings:
        :return: a dictionary including information on authorized keys
        :rtype: dict
        """
        params = {"username": username}
        if domain is not None:
            params["domain"] = domain
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        if settings is not None:
            params["settings"] = settings
        response = await super().handle_api_soap_request("AuthorizedKeys", params)
        return response

    async def recovery_keys(
        self,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method returns recovery SSH key configured on a specific client policy.

        :param str client: client policy
        :param str source: source IP
        :return: a dictionary including information of recovery key
        :rtype: dict
        """
        params = {"client": client}
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("RecoveryKeys", params)
        return response

    async def sudoers(
        self,
        username: str,
        domain: str = None,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method returns the list of sudo commands authorized for a specific user and client policy.

        :param str username: username of account.
        :param str domain: domain of user account
        :param str client: client policy
        :param str source: source IP
        :return: a dictionary including information on authorized keys
        :rtype: dict
        """
        params = {"username": username}
        if domain is not None:
            params["domain"] = domain
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("Sudoers", params)
        return response

    async def session_start(
        self,
        username: str,
        identity: str = None,
        domain: str = None,
        server: str = None,
        command: str = None,
        terminal: bool = None,
        client: str = None,
        source: str = None,
    ) -> dict:
        """
        This method starts an SSH session.

        :param str username: username of account.
        :param str identity: identity of account.
        :param str domain: domain of user account
        :param str server: server on which user connected to
        :param str command: command run by user
        :param str terminal: terminal of user
        :param str client: client policy
        :param str source: source IP
        :return: a dictionary including information on started session
        :rtype: dict
        """
        params = {"username": username}
        if identity is not None:
            params["identity"] = identity
        if domain is not None:
            params["domain"] = domain
        if server is not None:
            params["server"] = server
        if command is not None:
            params["command"] = command
        if terminal is not None:
            params["terminal"] = terminal
        if client is not None:
            params["client"] = client
        if source is not None:
            params["source"] = source
        response = await super().handle_api_soap_request("SessionStart", params)
        return response

    async def session_update(
        self,
        session: str,
        stop: bool = None,
        data: str = None,
        logs: str = None,
    ) -> dict:
        """
        This method updates data and logs of an existing SSH session.

        :param str session: session of SSH connection.
        :param str stop: boolean if session is stopping.
        :param str data: data of SSH connection
        :param str logs: logs of SSH connection
        :return: a dictionary including information on updated session
        :rtype: dict
        """
        params = {"session": session}
        if stop is not None:
            params["stop"] = stop
        if data is not None:
            if not re.compile(REGEX_BASE64).search(data):
                raise TypeError("data parameter is not base64")
            params["data"] = data
        if logs is not None:
            if not re.compile(REGEX_BASE64).search(logs):
                raise TypeError("logs parameter is not base64")
            params["logs"] = logs
        response = await super().handle_api_soap_request("SessionUpdate", params)
        return response

    async def session_login(
        self,
        session: str,
        password: str = None,
    ) -> dict:
        """
        This request makes a spankey login (i.e. check for LDAP password) of username corresponding to a session.

        :param str session: session of SSH connection.
        :param str password: password of user account
        :return: a dictionary including information on authentication
        :rtype: dict
        """
        return await self.authenticate_user("SessionLogin", session, password)

    async def session_unlock(
        self,
        session: str,
        password: str = None,
    ) -> dict:
        """
        This request makes a spankey unlock of a session.

        :param str session: session of SSH connection.
        :param str password: password of user account
        :return: a dictionary including information on authentication
        :rtype: dict
        """
        return await self.authenticate_user("SessionUnlock", session, password)

    async def authenticate_user(self, method, session, password):
        """
        This request makes a spankey authentication of a session.

        :param str method: spankey method
        :param str session: session of SSH connection.
        :param str password: password of user account
        :return: a dictionary including information on authentication
        :rtype: dict
        """
        params = {"session": session}
        if password is not None:
            params["password"] = password
        response = await super().handle_api_soap_request(method, params)
        return response

    async def password_change(
        self,
        session: str,
        old_password: str = None,
        new_password: str = None,
    ) -> dict:
        """
        This request changes the password of username corresponding to a session.

        :param str session: session of SSH connection.
        :param str old_password: current password of user account
        :param str new_password: new password of user account
        :return: a dictionary including information on password update
        :rtype: dict
        """
        params = {
            "session": session,
            "oldPassword": old_password,
            "newPassword": new_password,
        }
        response = await super().handle_api_soap_request("PasswordChange", params)
        return response
