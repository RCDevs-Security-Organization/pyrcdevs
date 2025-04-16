"""This module implements tests for SMSHub SOAP API."""

import asyncio
import re
import ssl
import time

import pytest

from pyrcdevs import SMSHubSoap
from pyrcdevs.soap.SMSHubSoap import SMSType
from tests.constants import (
    MSG_INVALID_SMS_REQUEST,
    MSG_INVALID_USERNAME,
    MSG_SMS_SENT,
    RANDOM_STRING,
    REGEX_STATUS_RESPONSE,
    SMS_MOBILE,
    SMSHUB_API_KEY,
    WEBADM_HOST,
)

smshub_soap_api = SMSHubSoap(
    WEBADM_HOST,
    8443,
    api_key=SMSHUB_API_KEY,
    verify_mode=ssl.CERT_NONE,
)


def test_status() -> None:
    """
    Test smshubStatus method.
    """
    response = asyncio.run(smshub_soap_api.status())
    assert all(prefix in response for prefix in ("status", "message"))
    assert response["status"]
    assert re.compile(REGEX_STATUS_RESPONSE).search(repr(response["message"]))


@pytest.mark.skip("Avoid using SMS credit")
def test_send() -> None:
    """
    Test smshubSend method.
    """
    # Testing with right mandatory arguments
    response = asyncio.run(
        smshub_soap_api.send("username", "password", [SMS_MOBILE], "test")
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing with right mandatory arguments and random sender
    response = asyncio.run(
        smshub_soap_api.send(
            "username", "password", [SMS_MOBILE], "test", sender=RANDOM_STRING
        )
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing with right mandatory arguments and not existing client policy
    response = asyncio.run(
        smshub_soap_api.send(
            "username", "password", [SMS_MOBILE], "test", client=RANDOM_STRING
        )
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing with right mandatory arguments and malformed source IP
    response = asyncio.run(
        smshub_soap_api.send(
            "username", "password", [SMS_MOBILE], "test", source=RANDOM_STRING
        )
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == "Server Error"

    # Testing with right mandatory arguments, and Flash as SMS type
    response = asyncio.run(
        smshub_soap_api.send(
            "username", "password", [SMS_MOBILE], "test", SMSType.FLASH
        )
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_SMS_SENT

    # Testing a wrong static username
    response = asyncio.run(
        smshub_soap_api.send(RANDOM_STRING, "password", [SMS_MOBILE], "test")
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing a wrong static password
    response = asyncio.run(
        smshub_soap_api.send("username", RANDOM_STRING, [SMS_MOBILE], "test")
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing an empty list of mobile phones
    response = asyncio.run(smshub_soap_api.send("username", "password", [], "test"))
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST

    # Testing an empty list text
    response = asyncio.run(
        smshub_soap_api.send("username", "password", [SMS_MOBILE], "")
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST

    # Testing with right mandatory arguments not right type for type_ parameter
    # noinspection PyTypeChecker
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        smshub_soap_api.send("username", "password", [SMS_MOBILE], "test", "Flash")
    assert str(excinfo).startswith("<ExceptionInfo TypeError('type_ is not SMSType')")


@pytest.mark.skip("Avoid using SMS credit")
def test_sign() -> None:
    """
    Test smshubSign method.
    """
    time.sleep(
        11
    )  # Waiting 11 seconds as previous test of send method may have added a blocking time
    # Testing a wrong static username
    response = asyncio.run(
        smshub_soap_api.sign(
            RANDOM_STRING,
            "password",
            [SMS_MOBILE],
            "test",
            30,
            RANDOM_STRING,
            "127.0.0.1",
        )
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing a wrong static password
    response = asyncio.run(
        smshub_soap_api.sign("username", RANDOM_STRING, [SMS_MOBILE], "test")
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Testing an empty list of mobile phones
    response = asyncio.run(smshub_soap_api.sign("username", "password", [], "test"))
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST

    # Testing an empty list text
    response = asyncio.run(
        smshub_soap_api.sign("username", "password", [SMS_MOBILE], "")
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_SMS_REQUEST
