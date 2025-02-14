"""This module implements tests for SpanKey SOAP API."""

import re
import time

import pytest

from pyrcdevs import SpanKeySoap
from pyrcdevs.soap.SpanKeySoap import NSSDatabaseType
from tests.constants import (
    AUDITD_COMMAND,
    CLUSTER_TYPE,
    DEFAULT_PASSWORD,
    MSG_INVALID_OR_NOT_FOUND_USER,
    MSG_INVALID_PASSWORD,
    MSG_INVALID_REQUEST,
    MSG_MISSING_SSH_KEY,
    MSG_OPERATION_SUCCESS,
    MSG_SERVER_ERROR,
    MSG_SESSION_NOT_STARTED,
    MSG_WELCOME_MESSAGE,
    RANDOM_STRING,
    REGEX_SESSION_FORMAT,
    REGEX_STATUS_RESPONSE,
    SETTING_SPANKEY,
    SPANKEY_API_KEY,
    SSH_KEY_BACKUP,
    TESTER_NAME,
    WEBADM_HOST,
)

spankey_soap_api = SpanKeySoap(
    WEBADM_HOST,
    8443,
    False,
    api_key=SPANKEY_API_KEY,
)


def test_status() -> None:
    """
    Test SpanKeyStatus method.
    """
    response = spankey_soap_api.status()
    assert all(prefix in response for prefix in ("status", "message"))
    assert response["status"]
    assert re.compile(REGEX_STATUS_RESPONSE).search(repr(response["message"]))


def test_nss_list() -> None:
    """
    Test spankeyNSSList method
    """
    # Test with non existing NSSDatabaseType
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        spankey_soap_api.nss_list(RANDOM_STRING)
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('database type is not NSSDatabaseType') tblen=2>"
    )

    # Test with malformed source IP
    response = spankey_soap_api.nss_list(
        NSSDatabaseType.USER,
        client=RANDOM_STRING,
        source=RANDOM_STRING,
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR
    assert response["data"] == {}

    # Test with non existing domain
    response = spankey_soap_api.nss_list(
        NSSDatabaseType.USER,
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain=RANDOM_STRING,
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR
    assert response["data"] == {}

    # Test for users
    response = spankey_soap_api.nss_list(
        NSSDatabaseType.USER, client=RANDOM_STRING, source="127.0.0.1", domain="Default"
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    pam_username = f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_pam" if CLUSTER_TYPE != "mssp" else f"u_pam"
    assert response["data"] == {
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1": {
            "gid": "100",  # NOSONAR
            "home": f"/home/u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
            "shell": "/bin/bash",  # NOSONAR
            "uid": "500",
        },
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2": {
            "gid": "100",
            "home": f"/home/u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2",
            "shell": "/bin/bash",
            "uid": "501",
        },
        pam_username: {
            "home": f"/home/{pam_username}",
            "uid": "502",
            "gid": "101",
            "shell": "/bin/bash",
        },
    }

    # Test for groups
    response = spankey_soap_api.nss_list(
        NSSDatabaseType.GROUP,
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["data"] == {
        f"g_{CLUSTER_TYPE}_api_1": {
            "gid": "100",
            "members": {
                "xsd:string": [
                    f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
                    f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2",
                ]
            },
        },
        f"g_{CLUSTER_TYPE}_api_2": {
            "gid": "101",
            "members": {
                "xsd:string": pam_username,
            },
        },
    }


def test_nss_info() -> None:
    """
    Test spankeyNSSInfo method
    """
    # Test with non existing NSSDatabaseType
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        spankey_soap_api.nss_info(RANDOM_STRING)
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('database type is not NSSDatabaseType') tblen=2>"
    )

    # Test with missing name or id parameter
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.USER,
        client=RANDOM_STRING,
        source=RANDOM_STRING,
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_REQUEST
    assert response["data"] is None

    # Test with non existing user
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.USER,
        client=RANDOM_STRING,
        name=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["data"] is None

    # Test with non existing group
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.GROUP,
        client=RANDOM_STRING,
        name=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["data"] is None

    # Test with malformed source IP
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.USER,
        client=RANDOM_STRING,
        source=RANDOM_STRING,
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_REQUEST
    assert response["data"] is None

    # Test with non existing domain
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.USER,
        name=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain=RANDOM_STRING,
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR
    assert response["data"] is None

    # Test with both id and name provided
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.USER,
        name=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        id_=500,
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain=RANDOM_STRING,
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_REQUEST
    assert response["data"] is None

    # Test with existing user
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.USER,
        name=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["data"] == {
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1": {
            "gid": "100",
            "home": f"/home/u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
            "shell": "/bin/bash",
            "uid": "500",
        }
    }

    # Test with existing group
    response = spankey_soap_api.nss_info(
        NSSDatabaseType.GROUP,
        name=f"g_{CLUSTER_TYPE}_api_1",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "data"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["data"] == {
        f"g_{CLUSTER_TYPE}_api_1": {
            "members": {
                "xsd:string": [
                    f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
                    f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2",
                ]
            },
            "gid": "100",
        }
    }


def test_authorized_keys() -> None:
    """
    Test spankeyAuthorizedKeys method
    """

    # Test with non existing user
    response = spankey_soap_api.authorized_keys(
        RANDOM_STRING,
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
        settings=SETTING_SPANKEY,
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "publicKeys",
            "backupKeys",
            "keyFiles",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_INVALID_OR_NOT_FOUND_USER
    assert response["publicKeys"] is None
    assert response["backupKeys"] == SSH_KEY_BACKUP
    assert response["keyFiles"] is None

    # Test with existing user with a SSH key enrolled
    response = spankey_soap_api.authorized_keys(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
        settings=SETTING_SPANKEY,
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "publicKeys",
            "backupKeys",
            "keyFiles",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert (
        response["publicKeys"]
        == f'environment="SPANKEY_USERNAME=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",environment="SPANKEY_DOMAIN=De'
        f'fault" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrpTE7AcY8TT47dvE5Xrhc3OYo9lO9bo7zOHGKCL/cva9a8srJjRb0DlpKZIZ'
        f"98v7b42i1eNFgc6DtPP8PHqBc/ywnNTOxXFaj2FIqitqOlLoK+z5cPVp7mnuq5TblDFFxXPeH6Sk/EAheFCkYMyZ+u2khEJ0I7/XLi6uLq"
        f"MpkAtjztdwo8Vq5UJzFKSuDftAgt4FTsuGwdEkJGWQsC6Enqu2uKDWygKpisfRXDvv2tkFdtA1spW4wVuYbc+YJuzmb+MLb1nRpAwRWzgO"
        f"ERPEGrKpJqoJJ2p8jtYas6OEvpG+1gAedzbGOWKNXqmE7GJy/Ay31D3H0IpcQPKjkHoM3 "
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1@Default"
    )
    assert response["backupKeys"] == SSH_KEY_BACKUP
    assert response["keyFiles"] is None

    # Test with existing user which is not activated or has no SSH key enrolled (for metadata)
    response = spankey_soap_api.authorized_keys(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
        settings=SETTING_SPANKEY,
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "publicKeys",
            "backupKeys",
            "keyFiles",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert (
        response["message"] == MSG_MISSING_SSH_KEY
        or response["message"] == MSG_INVALID_OR_NOT_FOUND_USER
    )
    assert response["publicKeys"] is None
    assert response["backupKeys"] == SSH_KEY_BACKUP
    assert response["keyFiles"] is None


def test_recovery_keys() -> None:
    """
    Test spankeyRecoveryKeys method
    """

    # Test with invalid source IP and non existing client policy
    response = spankey_soap_api.recovery_keys(
        RANDOM_STRING,
        source=RANDOM_STRING,
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "backupKeys",
        )
    )
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR
    assert response["backupKeys"] is None

    # Test with valid source IP and non existing client policy
    response = spankey_soap_api.recovery_keys(
        RANDOM_STRING,
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "backupKeys",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["backupKeys"] == SSH_KEY_BACKUP

    # Test with valid source IP and existing client policy
    response = spankey_soap_api.recovery_keys(
        "testclient",
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "backupKeys",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["backupKeys"] == SSH_KEY_BACKUP


def test_sudoers() -> None:
    """
    Test spankeySudoers method
    """

    # Test with non existing user
    response = spankey_soap_api.sudoers(
        RANDOM_STRING,
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "sudoAdvanced",
            "sudoCommands",
        )
    )
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR
    assert response["sudoAdvanced"] is None
    assert response["sudoCommands"] is None

    # Test with existing user with a SSH key enrolled, and a non existing client policy
    response = spankey_soap_api.sudoers(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "sudoAdvanced",
            "sudoCommands",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["sudoAdvanced"] == '"ALL=(ALL) /bin/df"'
    assert (
        response["sudoCommands"]
        == f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1 ALL=(ALL) /bin/touch"
    )

    # Test with existing user with a SSH key enrolled, and an existing client policy
    response = spankey_soap_api.sudoers(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        client="testclient",
        source="127.0.0.1",
        domain="Default",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "sudoAdvanced",
            "sudoCommands",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["sudoAdvanced"] == '"ALL=(ALL) /bin/df"'
    assert (
        response["sudoCommands"]
        == f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1 ALL=(ALL) /bin/touch"
    )

    # Test with existing user which is not activated or has no SSH key enrolled (for metadata)
    response = spankey_soap_api.sudoers(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2",
        client=RANDOM_STRING,
        source="127.0.0.1",
        domain="Default",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "sudoAdvanced",
            "sudoCommands",
        )
    )
    assert response["code"] in ["0", "1"]
    assert response["error"] in (None, "ServerError")
    assert response["message"] in [MSG_OPERATION_SUCCESS, MSG_SERVER_ERROR]
    assert response["sudoAdvanced"] in (None, '"ALL=(ALL) /bin/df"')
    assert response["sudoCommands"] in (
        None,
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2 ALL=(ALL) /bin/touch",
    )


def test_session_start() -> None:
    """
    Test spankeySessionStart method
    """

    # Test with non existing user
    response = spankey_soap_api.session_start(
        RANDOM_STRING,
        identity=RANDOM_STRING,
        domain="Default",
        server="ssh-server",
        command="/bin/bash",
        terminal=True,
        client=RANDOM_STRING,
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "offline",
            "publicKeys",
            "backupKeys",
        )
    )
    assert response["code"] == "0"
    assert response["error"] == "RequestFailed"
    assert response["message"] == MSG_INVALID_OR_NOT_FOUND_USER
    assert response["offline"] == "false"
    assert response["publicKeys"] is None
    assert response["backupKeys"] is None

    # Test with existing user
    response = spankey_soap_api.session_start(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        identity=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        server="ssh-server",
        command="/bin/bash",
        terminal=True,
        client=RANDOM_STRING,
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "session",
            "welcome",
            "maxtime",
            "locktime",
            "record",
            "auditd",
            "create",
            "delete",
            "offline",
            "code",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    assert response["welcome"] == MSG_WELCOME_MESSAGE
    assert response["maxtime"] == "1800"
    assert response["locktime"] == "60"
    assert response["record"] == "TTY LOG"
    assert response["auditd"] == AUDITD_COMMAND
    assert response["create"] == "true"
    assert response["delete"] == "false"
    assert response["offline"] == "true"


def test_session_update() -> None:
    """
    Test spankeySessionUpdate method
    """

    # Test with non existing session
    response = spankey_soap_api.session_update(
        RANDOM_STRING,
        stop=False,
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
        )
    )
    assert response["code"] == "0"
    assert response["error"] == "NoSession"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start a SSH connection in order to get an existing session
    response = spankey_soap_api.session_start(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        identity=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        terminal=True,
        client=RANDOM_STRING,
        domain="Default",
        server="ssh-server",
        command="/bin/bash",
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "session",
            "record",
            "auditd",
            "create",
            "welcome",
            "maxtime",
            "locktime",
            "delete",
            "offline",
            "code",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    existing_session = response["session"]
    assert response["auditd"] == AUDITD_COMMAND
    assert response["create"] == "true"
    assert response["welcome"] == MSG_WELCOME_MESSAGE
    assert response["maxtime"] == "1800"
    assert response["locktime"] == "60"
    assert response["record"] == "TTY LOG"
    assert response["delete"] == "false"
    assert response["offline"] == "true"

    # Test with existing session but not base64 data
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        spankey_soap_api.session_update(RANDOM_STRING, data="!")
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('data parameter is not base64') tblen=2>"
    )

    # Test with existing session but not base64 logs
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        spankey_soap_api.session_update(RANDOM_STRING, logs="!")
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('logs parameter is not base64') tblen=2>"
    )

    # Test with existing session
    response = spankey_soap_api.session_update(
        existing_session,
        stop=False,
        data="AQEBeJxjZGBg4GLYx2DABGTIMfhJR9sbGRiYZEjHGliXpBaXlBanFjkUFyTmZadWWinUsUtHGxhaGxvlossBxQ1yrSCyJrl1YK6KAtBQl"
        "joGQaihOby8XKkVmSW8XADo9h4+/mdatamlogsxsitypexsdbase64BinaryAQEBeJztmk1v2zgQhu/7KwiftofEJCWSUgAeAsfBLpBuF"
        "22w254WEkU5KmxLEKU2+fdL2aY+YidyZcetbQUINCTFiWY47yOTTvaUSP7py6fR9d0dmKkJ9/Igyn5HzLKpCxGmlwhaVxZ13l0BLxUPXM"
        "Dix5JAPSnhTaecuEDlQkil+JNUQD5GGYfAg5yFYcBCHzpCBMBDq7YXMsz0OObYC6FkWNuWHnNsSdyQMRuCKJMzxTFIkijglBEbLA2KgJd"
        "ri0AEzHWirwhCIE2HMkZYWtLcpIwRllaWPfEkU3qeVNwFIp7N+MD31MNARyL5YJirdOhH8+GyT+X+V57PRTwPo7kMBr9lff52z9/483j0"
        "z7g9fRPBUZGZQeVxTw5G/960zRbfAz3vIZ7JYSZVliuZ7mPy39f3f7TNLhZU18Tcm8n6o4NoHgeSE2xbugoC+Y2HwZVek1nRC/XqMEJAX"
        "KwiBPFkcUmLuyAs7iq8LZ7grw8f31/fAeEl/4WJvmdhRMaQxvgmU2OmcZwV7s4uAmQimEY+tYfT4GIazfPHi0eHXlD7UsWXuIqJUET7mP"
        "Ya08cPo/s/7+9alZ6ksciibCrXlb4PHy28Z9qD++O8J0RiLJAtacF0VLUZXPC+bIdL5pu2R/Aa8zXqVwY9EPMnaZwn6jn1TW8X7ldpLLG"
        "9cteKXTO1G3bN7Ca0noe0koSFHQf/mjJvxHFKMjeB1STaqIxen70+e30eqz4RurIY7K5PX7CGPoWNG/r0V/p0VqK01kXJDiTKqY4iiRL5"
        "XJZB181SLXdalLja6xT+dE6qP1H+6Taxli47ibWcvVmsVQKMXCEi6OeVdl+ZO1Tm1mWA6hvB5jaQOD9v8d9GWVtnBR/PG2A3WrS8PkoX1"
        "esD31JMXTrGt0xvziDUV8Ishqt+OqJFj55IXf1LzhBMqAOYKHIkdmDgu0sw6bYPHeQzsQSTGfdcpwDT+udYZsDkHO5sURZZ3XC+uOo/Vz"
        "ihJpyqhJwbnQ4ImBYQoldB2Gv6jTWNXsR75dngHWHbPTt1oyPcfe4kua3QgBpo0ADQd1BCxzrsG0r29+njeMqzhVREB4M7kwq5PipJtWh"
        "7sE4q3UYvkMpdkarYVh2EVEGUbgJV2d1ly15lr1R36a8X91qajkDc5lE3i7tc3OqEktm9to9U21vXwRGpsFVIJrCakPQgwz8uo7dBY0tN"
        "u9qt1fkYjzqE1o/xdHhu/RhPj4vGMd76tz7sUP+Jo7Ml4mmcrn3xUxvYXNe7kfhU4Ph6eVZ1VC9Pk9eiQC/8E8bEKyViMrPDy3p/jHkt9"
        "+ZBX6xGs5q1erR+2Zd1D7Z2sG1dDUekxP1hqk2VxteaKi1aqO+WYWZpZd5QvA9GnI5wT7Hq9lks/wPYGvO",
        logs="AQEBeJztmltvo0YYhu/7K5Cv2gvHcx6IxEXkOGqltFvtRt3tVcVhcKiwQYC3yb/fwWYAxwcIOK6xiBR5DszAfIfnZcZOXyNhfvn7y/Tu8"
        "VFbJHPTWrl++jPkmDBD1xm+YQzfUg5+udWs2Hk2HZD9YaElr4ljBYFJDS1ZOY5IEvNVJJp48VMTaBYwued5OhW65TiOZkFV5zqCsh+ZhH"
        "mMI1nEsstwmY2Z4ARofioWiYm0KPJdE0KAuJaXMNOslSxSADX1Oc+6ANCEakhUwStKQl2UqIJXlNL01YzSRI4T8qZQc8LFwhzZVvI8kms"
        "R5miySuKJ7S8nm7ZkZf9rrpZOuPT8pXBHP6WZBWffZtO/ZvUGnDsmzGwzKmfcTDC4oKsLpl/v66zn/OfKyZ7DhZikIklXiYjzwX/ePf1a"
        "NzozijTr0lqIqv80fxm6wqSIYGlJV3w3PfdWrmqRtQK5Pk6pFmZ2AFo4X3/E2VUAZFdls62f4I9Pn3+/e9QcK/rHi+Q164KvCkIVvotYF"
        "eMwTLPpThSBjU0AlQkC32ZkErjjwF+uXsYvOhszcpOEN6g0CmWQ/X9G6RYTnz9Nn357eqw1ahSHTuqngehg1IuNqxowcbkI+H4wUcoYQR"
        "xZLKMPLOscrMFU1L0NnVSdUbRLJ8kkVTLORad5HK6i5C2fVOt+Ql1jhh3HThkdBXZyE50uxY7kuLr94Rwfovtk0d0xEo7khhq7Dcq3T5X"
        "nA0a6ji5SceqjsbERegSIa3FsLarUYiqoahfhPXJuA3yi9vjkDt/Cp07QFj55jk89Zybew0y5mTkTMwO5kMiPxFtqukf2LJ2DanBANwfU"
        "ixZSooXKXVM2nzRLeYvi1h85a420oKPS0mlwHbrQQYaXPlEUB5DCy1UjtANh5ZlyN0b1Hjz/9XgC9UcOex9dTeQIbckRemCIGWyGHjhmO"
        "gDyk3LMUdnOpixrwRwwQ/7T63X/cTHmUC4LtxFj24LYcg3byMXYNoTDOeROLsZ5v2XomRjv7iClBKsSPOPprcgMu+cEN2/v8EZ0mhA8qt"
        "IVbxUqXT77MZkeoqB7FBx+Wyns1+ptpRi9XyPLx1IaCRExLvRwrX2ENjZQj3ai3SKmBjrFFCV0JFrkFYyymVz2PaMnUb6ehWcD0pHWpBP"
        "Uhop0m7oFqqSTdXiIdKggHT4X6Vw/3ge6ornF9rNiwCLBi/mG/N4xU0/ymxzM78K55YknJ0N69ze9G4dCjxLxg5DVJEPJdobKTo7en5/d"
        "SHItyX2NoXnGIKphI5U3oq3P3QmhrHruLqtG9dxd9jtb5+77viwm5IxsdMIgjHe+L650tHn9KY1YZYmaMaPJ2K7fL6pZ2uW0Gn0wp9XjV"
        "LIaX6xkD2HZKCwbB8Q1sVEtbIeNmGUMfOCIY8nHe4aG3D27Ig9Rh2oBZ9wgoMvpWHvAYbz1ey1CiFUFHJXxUQ+4s/1AOtghW9BCabfNJr"
        "MVr7M1UGk6XmeJHJWGo8wWo3FQf9A9+OLMvjgA0eqE7/5tQLPBh7BVHX3gG+kSvUi+cV/gZugq19An+bjGNR2TxOrCKpI43YiglMFCFvE"
        "9g3KrStjDWh6nHzv5D0MzMVc=",
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "session",
            "welcome",
            "maxtime",
            "locktime",
            "record",
            "auditd",
            "create",
            "delete",
            "offline",
            "code",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["session"] is None
    assert response["welcome"] is None
    assert response["maxtime"] == "0"
    assert response["locktime"] == "0"
    assert response["record"] is None
    assert response["auditd"] is None
    assert response["create"] == "false"
    assert response["delete"] == "false"
    assert response["offline"] == "false"


def test_session_login() -> None:
    """
    Test spankeySessionLogin method
    """

    # Test with non existing session
    response = spankey_soap_api.session_login(
        RANDOM_STRING,
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
        )
    )
    assert response["code"] == "0"
    assert response["error"] == "NoSession"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start a SSH connection in order to get an existing session
    response = spankey_soap_api.session_start(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        identity=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        server="ssh-server",
        command="/bin/bash",
        terminal=True,
        client="testclient",
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "session",
            "welcome",
            "maxtime",
            "locktime",
            "record",
            "auditd",
            "create",
            "delete",
            "offline",
            "code",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    existing_session = response["session"]
    assert response["welcome"] == MSG_WELCOME_MESSAGE
    assert response["maxtime"] == "1800"
    assert response["locktime"] == "60"
    assert response["record"] == "TTY LOG"
    assert response["auditd"] == AUDITD_COMMAND
    assert response["create"] == "true"
    assert response["delete"] == "false"
    assert response["offline"] == "true"

    time.sleep(2)

    # Test with existing session but wrong password
    response = spankey_soap_api.session_login(existing_session, password=RANDOM_STRING)
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS

    # Test with existing session but right password
    response = spankey_soap_api.session_login(
        existing_session, password=DEFAULT_PASSWORD
    )
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
        )
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_OPERATION_SUCCESS


def test_session_unlock() -> None:
    """
    Test spankeySessionUnlock method
    """

    # Test with non existing session
    response = spankey_soap_api.session_unlock(
        RANDOM_STRING,
        RANDOM_STRING,
    )
    assert all(
        prefix in response
        for prefix in (
            "message",
            "code",
            "error",
        )
    )
    assert response["error"] == "NoSession"
    assert response["code"] == "0"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start a new SSH connection in order to get an existing session
    response = spankey_soap_api.session_start(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        identity=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        terminal=True,
        client="testclient",
        server="ssh-server",
        command="/bin/bash",
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "session",
            "record",
            "auditd",
            "create",
            "welcome",
            "maxtime",
            "locktime",
            "delete",
            "offline",
            "code",
        )
    )
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["code"] == "1"
    assert response["error"] is None
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    existing_session = response["session"]
    assert response["welcome"] == MSG_WELCOME_MESSAGE
    assert response["create"] == "true"
    assert response["delete"] == "false"
    assert response["offline"] == "true"
    assert response["maxtime"] == "1800"
    assert response["locktime"] == "60"
    assert response["record"] == "TTY LOG"
    assert response["auditd"] == AUDITD_COMMAND

    time.sleep(2)

    # Test with existing session but wrong password
    response = spankey_soap_api.session_unlock(existing_session, password=RANDOM_STRING)
    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
        )
    )
    assert response["code"] == "2"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_PASSWORD

    # Test with existing session but right password
    response = spankey_soap_api.session_unlock(
        existing_session, password=DEFAULT_PASSWORD
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "session",
            "record",
            "auditd",
            "create",
            "welcome",
            "maxtime",
            "locktime",
            "delete",
            "offline",
            "code",
        )
    )
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["session"] is None
    assert response["welcome"] is None
    assert response["create"] == "false"
    assert response["delete"] == "false"
    assert response["offline"] == "false"
    assert response["maxtime"] == "0"
    assert response["locktime"] == "0"
    assert response["record"] is None
    assert response["auditd"] is None


def test_password_change() -> None:
    """
    Test spankeyPasswordChange method
    """

    # Test with non existing session
    response = spankey_soap_api.password_change(
        RANDOM_STRING,
        RANDOM_STRING,
        RANDOM_STRING,
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "code",
        )
    )
    assert response["message"] == MSG_SESSION_NOT_STARTED
    assert response["error"] == "NoSession"
    assert response["code"] == "0"

    # Start a new SSH connection in order to get an existing session
    response = spankey_soap_api.session_start(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        terminal=True,
        identity=f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        client="testclient",
        server="ssh-server",
        command="/bin/bash",
        source="127.0.0.1",
    )
    assert all(
        prefix in response
        for prefix in (
            "delete",
            "offline",
            "error",
            "message",
            "session",
            "record",
            "auditd",
            "create",
            "welcome",
            "maxtime",
            "locktime",
            "code",
        )
    )

    assert response["record"] == "TTY LOG"
    assert response["auditd"] == AUDITD_COMMAND
    assert response["message"] == MSG_OPERATION_SUCCESS
    assert response["code"] == "1"
    assert response["error"] is None
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    existing_session = response["session"]
    assert response["welcome"] == MSG_WELCOME_MESSAGE
    assert response["create"] == "true"
    assert response["delete"] == "false"
    assert response["offline"] == "true"
    assert response["maxtime"] == "1800"
    assert response["locktime"] == "60"

    time.sleep(2)

    # Test with existing session but wrong current password
    response = spankey_soap_api.password_change(
        existing_session,
        RANDOM_STRING,
        "new password",
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "code",
        )
    )
    assert response["error"] == "AuthFailed"
    assert response["code"] == "2"
    assert response["message"] == MSG_INVALID_PASSWORD

    # Test with existing session, right current password but same new password
    response = spankey_soap_api.password_change(
        existing_session,
        DEFAULT_PASSWORD,
        DEFAULT_PASSWORD,
    )
    assert all(
        prefix in response
        for prefix in (
            "error",
            "message",
            "code",
        )
    )
    assert response["error"] == "PasswordPolicy"
    assert response["code"] == "0"
    assert response["message"] == "Password does not match the password policy"

    # Test with existing session, right current password and different new password
    response = spankey_soap_api.password_change(
        existing_session,
        DEFAULT_PASSWORD,
        f"{RANDOM_STRING}!",
    )
    assert all(
        prefix in response
        for prefix in (
            "message",
            "code",
            "error",
        )
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert response["message"] == MSG_OPERATION_SUCCESS
