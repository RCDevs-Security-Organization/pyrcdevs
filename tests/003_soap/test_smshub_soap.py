"""This module implements tests for SMSHub SOAP API."""

import os
import re
import secrets
import string
import time

import pytest

from pyrcdevs import SMSHubSoap
from pyrcdevs.soap.SMSHubSoap import SMSType

MSG_INVALID_SMS_REQUEST = "Invalid SMS request"

MSG_SMS_SENT = "SMS send success"

MSG_AUTH_SUCCESS = "Authentication success"

MSG_INVALID_USERNAME = "Invalid username or password"

RANDOM_STRING = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(10)
)
RANDOM_CONTEXT = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
)
RANDOM_RETRYID = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
)
REGEX_STATUS_RESPONSE = (
    r"Server: SMS Hub Server [0-9.]+ \(WebADM [0-9.]+\)\\r\\nSystem: Linux "
    r"[a-z0-9.\-_]*.x86_64 x86_64 \(\d* bit\)\\r\\nListener: (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]"
    r"[0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]* \(HTTP\/1.1\)\\r"
    r"\\nUptime: \d*s \(\d* days\)\\r\\nCluster Node: \d*\/\d* \(Session Server\)\\r\\nLocal "
    r"Memory: \d*M \(\d*M total\)\\r\\nShared Memory: \d*M \(\d*M total\)\\r\\nConnectors: OK "
    r"\(\d* alive & 0 down\)"
)

REGEX_SESSION_FORMAT = r"^[a-zA-Z0-9]{16,17}$"
REGEX_TIMEOUT = r"[0-9*]"

webadm_host = os.environ["WEBADM_HOST"]
sms_mobile = os.environ["SMS_MOBILE"]
smshub_soap_api = SMSHubSoap(
    webadm_host,
    "8443",
    False,
    api_key="5860687476061196336_d788fd99ea4868f35c3b5e21ada3920b9501bb2c",
)


def test_status() -> None:
    """
    Test smshubStatus method.
    """
    response = smshub_soap_api.status()
    assert all(prefix in response for prefix in ("status", "message"))
    assert response["status"]
    assert re.compile(REGEX_STATUS_RESPONSE).search(repr(response["message"]))


@pytest.mark.skip("Avoid using sms credits")
def test_send() -> None:
    """
    Test smshubSend method.
    """
    # Testing with right mandatory arguments
    response = smshub_soap_api.send("username", "password", [sms_mobile], "test")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing with right mandatory arguments and random sender
    response = smshub_soap_api.send(
        "username", "password", [sms_mobile], "test", sender=RANDOM_STRING
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing with right mandatory arguments and not existing client policy
    response = smshub_soap_api.send(
        "username", "password", [sms_mobile], "test", client=RANDOM_STRING
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing with right mandatory arguments and malformed source IP
    response = smshub_soap_api.send(
        "username", "password", [sms_mobile], "test", source=RANDOM_STRING
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == "Server Error"

    # Testing with right mandatory arguments, and Flash as SMS type
    response = smshub_soap_api.send(
        "username", "password", [sms_mobile], "test", SMSType.FLASH
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing a wrong static username
    response = smshub_soap_api.send(RANDOM_STRING, "password", [sms_mobile], "test")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing a wrong static password
    response = smshub_soap_api.send("username", RANDOM_STRING, [sms_mobile], "test")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing an empty list of mobile phones
    response = smshub_soap_api.send("username", "password", [], "test")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST

    # Testing an empty list text
    response = smshub_soap_api.send("username", "password", [sms_mobile], "")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST

    # Testing with right mandatory arguments not right type for type_ parameter
    # noinspection PyTypeChecker
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        smshub_soap_api.send("username", "password", [sms_mobile], "test", "Flash")
    assert str(excinfo) == "<ExceptionInfo TypeError('type_ is not SMSType') tblen=2>"


@pytest.mark.skip("Avoid using sms credits")
def test_sign() -> None:
    """
    Test smshubSign method.
    """
    time.sleep(
        11
    )  # Waiting 11 seconds as previous test of send method may have added a blocking time
    # Testing a wrong static username
    response = smshub_soap_api.sign(
        RANDOM_STRING, "password", [sms_mobile], "test", 30, RANDOM_STRING, "127.0.0.1"
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing a wrong static password
    response = smshub_soap_api.sign("username", RANDOM_STRING, [sms_mobile], "test")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing an empty list of mobile phones
    response = smshub_soap_api.sign("username", "password", [], "test")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST

    # Testing an empty list text
    response = smshub_soap_api.sign("username", "password", [sms_mobile], "")
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST
