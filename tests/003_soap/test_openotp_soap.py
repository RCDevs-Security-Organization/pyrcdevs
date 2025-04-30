"""This module implements tests for OpenOTP SOAP API."""

import re
import ssl
import time

import pytest

from pyrcdevs import OpenOTPSoap
from pyrcdevs.constants import REGEX_BASE64, TYPE_BASE64_STRING
from pyrcdevs.soap.OpenOTPSoap import QRCodeFormat, SignatureMode
from tests.constants import (
    BASE64_STRING,
    CLUSTER_TYPE,
    DEFAULT_PASSWORD,
    EXCEPTION_NOT_RIGHT_TYPE,
    LIST_COUNTRY_NAMES,
    MSG_AUTH_SUCCESS,
    MSG_ENTER_EMERGENCY_OTP,
    MSG_INVALID_AUTH_REQUEST,
    MSG_INVALID_USERNAME,
    MSG_MOBILE_AUTH_CANCELED,
    MSG_SERVER_ERROR,
    MSG_SESSION_ALREADY_STARTED,
    MSG_SESSION_NOT_STARTED,
    OPENOTP_API_KEY,
    PDF_FILE_BASE64,
    RANDOM_CONTEXT,
    RANDOM_DATA,
    RANDOM_RETRYID,
    RANDOM_SESSION,
    RANDOM_STRING,
    REGEX_ADDRESS,
    REGEX_ASYNC_CONFIRM,
    REGEX_ASYNC_SIGN,
    REGEX_COORDINATES,
    REGEX_IPV4,
    REGEX_SESSION_FORMAT,
    REGEX_STATUS_RESPONSE,
    REGEX_TIMEOUT,
    SETTINGS_LOGINMODE_LDAP,
    SIGNATURE_DATA,
    TESTER_NAME,
    USER_CERT_PATH,
    WEBADM_HOST,
)

openotp_soap_api = OpenOTPSoap(
    WEBADM_HOST,
    8443,
    api_key=OPENOTP_API_KEY,
    verify_mode=ssl.CERT_NONE,
)


@pytest.mark.asyncio
async def test_status() -> None:
    """
    Test openotpStatus method.
    """
    status_response = await openotp_soap_api.status()
    assert all(prefix in status_response for prefix in ("status", "message"))
    assert status_response["status"]
    assert re.compile(REGEX_STATUS_RESPONSE).search(repr(status_response["message"]))


@pytest.mark.asyncio
async def test_simple_login() -> None:
    """
    Test openotpSimpleLogin method.
    """
    # Test not existing username
    response = await openotp_soap_api.simple_login(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username but not existing Domain
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, but no password
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", domain="Default"
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, but wrong password
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        any_password=RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, and right password
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        any_password=DEFAULT_PASSWORD,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout", "otpChallenge")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert response["message"] == MSG_ENTER_EMERGENCY_OTP
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    assert re.compile(REGEX_TIMEOUT).search(response["timeout"])
    assert response["otpChallenge"] == "EMERG"

    # Test all valid settings (settings is configured so only LDAP password is checked)
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        any_password=DEFAULT_PASSWORD,
        client="OpenOTP",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        options="",
        context=RANDOM_CONTEXT,
        retry_id=RANDOM_RETRYID,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS

    # Test all valid settings (settings is configured so only OTP password is checked)
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        any_password="123456",  # NOSONAR
        client="OpenOTP",
        source="127.0.0.1",
        settings="OpenOTP.LoginMode=OTP",
        options="",
        context=RANDOM_CONTEXT,
        retry_id=RANDOM_RETRYID,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS


@pytest.mark.asyncio
async def test_normal_login() -> None:
    """
    Test openotpNormalLogin method.
    """
    # Test not existing username
    response = await openotp_soap_api.normal_login(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username but not existing Domain
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, but no password
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", domain="Default"
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, but wrong ldap password
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        ldap_password=RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, and right ldap password
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        ldap_password=DEFAULT_PASSWORD,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout", "otpChallenge")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert response["message"] == MSG_ENTER_EMERGENCY_OTP
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    assert re.compile(REGEX_TIMEOUT).search(response["timeout"])
    assert response["otpChallenge"] == "EMERG"

    # Test existing username, existing Domain, right ldap password, and wrong otp password
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        ldap_password=DEFAULT_PASSWORD,
        otp_password=RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test existing username, existing Domain, right ldap password, and right otp password
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        ldap_password=DEFAULT_PASSWORD,
        otp_password="123456",  # NOSONAR
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS

    # Test all valid settings (settings is configured so only LDAP password is checked)
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        ldap_password=DEFAULT_PASSWORD,  # NOSONAR
        otp_password=RANDOM_STRING,  # NOSONAR
        client="OpenOTP",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        options="",
        context=RANDOM_CONTEXT,
        retry_id=RANDOM_RETRYID,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS

    # Test all valid settings (settings is configured so only OTP password is checked)
    response = await openotp_soap_api.normal_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        ldap_password=RANDOM_STRING,  # NOSONAR
        otp_password="123456",  # NOSONAR
        client="OpenOTP",
        source="127.0.0.1",
        settings="OpenOTP.LoginMode=OTP",
        options="",
        context=RANDOM_CONTEXT,
        retry_id=RANDOM_RETRYID,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS


@pytest.mark.asyncio
async def test_pki_login() -> None:
    """
    Test openotpPKILogin method.
    """
    # Test malformed certificate
    response = await openotp_soap_api.pki_login(
        RANDOM_STRING,
        client="testclient",
        source="",
        settings="",
        options="",
        context="",
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test unknown certificate
    response = await openotp_soap_api.pki_login(
        "-----BEGIN CERTIFICATE-----\n"
        "MIICMzCCAZygAwIBAgIJALiPnVsvq8dsMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV\n"
        "BAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNVBAcTA2ZvbzEMMAoGA1UEChMDZm9v\n"
        "MQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2ZvbzAeFw0xMzAzMTkxNTQwMTlaFw0x\n"
        "ODAzMTgxNTQwMTlaMFMxCzAJBgNVBAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNV\n"
        "BAcTA2ZvbzEMMAoGA1UEChMDZm9vMQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2Zv\n"
        "bzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdGfxi9CNbMf1UUcvDQh7MYB\n"
        "OveIHyc0E0KIbhjK5FkCBU4CiZrbfHagaW7ZEcN0tt3EvpbOMxxc/ZQU2WN/s/wP\n"
        "xph0pSfsfFsTKM4RhTWD2v4fgk+xZiKd1p0+L4hTtpwnEw0uXRVd0ki6muwV5y/P\n"
        "+5FHUeldq+pgTcgzuK8CAwEAAaMPMA0wCwYDVR0PBAQDAgLkMA0GCSqGSIb3DQEB\n"
        "BQUAA4GBAJiDAAtY0mQQeuxWdzLRzXmjvdSuL9GoyT3BF/jSnpxz5/58dba8pWen\n"
        "v3pj4P3w5DoOso0rzkZy2jEsEitlVM2mLSbQpMM+MUVQCQoiG6W9xuCFuxSrwPIS\n"
        "pAqEAuV4DNoxQKKWmhVv+J0ptMWD25Pnpxeq5sXzghfJnslJlQND\n"
        "-----END CERTIFICATE-----"
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for a valid certificate
    with open(USER_CERT_PATH, "rb") as user_cert_file:
        user_cert = user_cert_file.read()
    response = await openotp_soap_api.pki_login(user_cert.decode())
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS


@pytest.mark.asyncio
async def test_challenge() -> None:
    """
    Test openotpChallenge method.
    """
    # Test for bad session length
    response = await openotp_soap_api.challenge(
        RANDOM_STRING, RANDOM_STRING, RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for not existing session
    response = await openotp_soap_api.challenge(
        RANDOM_STRING, RANDOM_SESSION, RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "NoSession"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start valid authentication
    response = await openotp_soap_api.simple_login(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        any_password=DEFAULT_PASSWORD,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout", "otpChallenge")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert response["message"] == MSG_ENTER_EMERGENCY_OTP
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert re.compile(REGEX_TIMEOUT).search(response["timeout"])
    assert response["otpChallenge"] == "EMERG"

    # Test with existing session but wrong username
    response = await openotp_soap_api.challenge(
        RANDOM_STRING, session, RANDOM_STRING, domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test with existing session and right username and OTP
    response = await openotp_soap_api.challenge(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        session,
        "123456",
        domain="Default",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS


@pytest.mark.skip("Requires user interaction")
@pytest.mark.asyncio
async def test_normal_confirm() -> None:
    """
    Test openotpNormalConfirm method.
    """
    # Test for too short data
    response = await openotp_soap_api.normal_confirm(RANDOM_STRING, RANDOM_STRING)

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for invalid user
    response = await openotp_soap_api.normal_confirm(RANDOM_STRING, RANDOM_DATA)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for invalid user
    response = await openotp_soap_api.normal_confirm(
        RANDOM_STRING, RANDOM_DATA, domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for malformed source IP
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source=RANDOM_STRING,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR

    # Test for valid confirm
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS

    # Test for file parameter not a base64 string
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await openotp_soap_api.normal_confirm(
            f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
            RANDOM_DATA,
            domain="Default",
            async_=False,
            timeout=60,
            issuer=RANDOM_STRING,
            client="testclient",
            source="127.0.0.1",
            settings=SETTINGS_LOGINMODE_LDAP,
            virtual="",
            file=RANDOM_STRING,
        )

    assert str(excinfo) == EXCEPTION_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING)

    # Test for too small file
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=BASE64_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for valid signature
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )

    assert all(prefix in response for prefix in ("code", "error", "message", "file"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS
    assert re.compile(REGEX_BASE64).search(response["file"])


@pytest.mark.asyncio
async def test_check_confirm() -> None:
    """
    Test openotpCheckConfirm method.
    """
    # Test for too short session length
    response = await openotp_soap_api.check_confirm(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing session
    response = await openotp_soap_api.check_confirm(RANDOM_SESSION)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "NoSession"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start an asynchronous signature
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=True,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["timeout"] == "60"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)

    time.sleep(1)

    # Test for status of existing session
    response = await openotp_soap_api.check_confirm(session)
    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert int(response["timeout"]) < 60
    assert response["error"] is None
    assert response["message"] == MSG_SESSION_ALREADY_STARTED
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])

    # Start an asynchronous confirm
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=True,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test for status of existing session
    response = await openotp_soap_api.check_confirm(session)
    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert response["message"] == MSG_SESSION_ALREADY_STARTED
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])
    assert int(response["timeout"]) < 60


@pytest.mark.asyncio
async def test_cancel_confirm() -> None:
    """
    Test openotpCancelConfirm method.
    """
    # Test for too short session length
    response = await openotp_soap_api.cancel_confirm(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing session
    response = await openotp_soap_api.cancel_confirm(RANDOM_SESSION)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "NoSession"
    assert response["code"] == "0"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start an asynchronous signature
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        domain="Default",
        async_=True,
        timeout=60,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test for cancelling existing session
    response = await openotp_soap_api.cancel_confirm(session)
    assert all(prefix in response for prefix in ("code", "message"))
    assert response["code"] == "1"
    assert response["message"] == MSG_MOBILE_AUTH_CANCELED

    # Start an asynchronous confirm
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=True,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    session = response["session"]
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test for cancelling existing session
    response = await openotp_soap_api.cancel_confirm(session)
    assert all(prefix in response for prefix in ("code", "message"))
    assert response["code"] == "1"
    assert response["message"] == MSG_MOBILE_AUTH_CANCELED


@pytest.mark.asyncio
async def test_touch_confirm() -> None:
    """
    Test openotpTouchConfirm method.
    """
    # Test for too short session length
    response = await openotp_soap_api.touch_confirm(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing session
    response = await openotp_soap_api.touch_confirm(RANDOM_SESSION)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "NoSession"
    assert response["code"] == "0"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start an asynchronous signature
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        domain="Default",
        async_=True,
        timeout=60,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test with existing session
    response = await openotp_soap_api.touch_confirm(session)
    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "timeout", "qrImage")
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    assert int(response["timeout"]) < 60
    assert re.compile(REGEX_BASE64).search(response["qrImage"])

    # Start an asynchronous confirm
    response = await openotp_soap_api.normal_confirm(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        domain="Default",
        async_=True,
        timeout=60,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test with existing session
    response = await openotp_soap_api.touch_confirm(
        session,
        send_push=False,
        qr_format=QRCodeFormat.JPG,
        qr_sizing=10,
        qr_margin=10,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "timeout", "qrImage")
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    assert int(response["timeout"]) < 60
    assert re.compile(REGEX_BASE64).search(response["qrImage"])

    # Test with existing session but wrong type for QR format
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await openotp_soap_api.touch_confirm(session, qr_format="PNG")
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('qr_format parameter is not QRCodeFormat')"
    )


@pytest.mark.asyncio
async def test_confirm_qr_code() -> None:
    """
    Test openotpConfirmQRCode method.
    """
    # Test for too short data
    response = await openotp_soap_api.confirm_qr_code(RANDOM_STRING, RANDOM_STRING)

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for invalid user
    response = await openotp_soap_api.confirm_qr_code(RANDOM_STRING, RANDOM_DATA)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for invalid user
    response = await openotp_soap_api.confirm_qr_code(
        RANDOM_STRING, RANDOM_DATA, domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for malformed source IP
    response = await openotp_soap_api.confirm_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source=RANDOM_STRING,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR

    # Test for valid confirm
    response = await openotp_soap_api.confirm_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        qr_format=QRCodeFormat.JPG,
        qr_sizing=10,
        qr_margin=10,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "timeout", "qrImage")
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    assert int(response["timeout"]) <= 60
    assert re.compile(REGEX_BASE64).search(response["qrImage"])

    # Test for file parameter not a base64 string
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await openotp_soap_api.confirm_qr_code(
            f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
            RANDOM_DATA,
            domain="Default",
            timeout=60,
            issuer=RANDOM_STRING,
            client="testclient",
            source="127.0.0.1",
            settings=SETTINGS_LOGINMODE_LDAP,
            virtual="",
            file=RANDOM_STRING,
        )

    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING)
    )

    # Test for too small file
    response = await openotp_soap_api.confirm_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=BASE64_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for valid signature
    response = await openotp_soap_api.confirm_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
        qr_format=QRCodeFormat.JPG,
        qr_sizing=10,
        qr_margin=10,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "timeout", "qrImage")
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert re.compile(REGEX_ASYNC_CONFIRM).search(response["message"])
    assert int(response["timeout"]) <= 60
    assert re.compile(REGEX_BASE64).search(response["qrImage"])


@pytest.mark.skip("Requires user interaction")
@pytest.mark.asyncio
async def test_normal_sign() -> None:
    """
    Test openotpNormalConfirm method.
    """
    # Test for too short data
    response = await openotp_soap_api.normal_sign(RANDOM_STRING, RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for invalid user
    response = await openotp_soap_api.normal_sign(RANDOM_STRING, RANDOM_DATA)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for invalid user
    response = await openotp_soap_api.normal_sign(
        RANDOM_STRING, RANDOM_DATA, domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for malformed source IP
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source=RANDOM_STRING,
        settings=SETTINGS_LOGINMODE_LDAP,
        mode=SignatureMode.PaDES,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR

    # Test for file parameter not a base64 string
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await openotp_soap_api.normal_sign(
            f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
            RANDOM_DATA,
            domain="Default",
            async_=False,
            timeout=60,
            issuer=RANDOM_STRING,
            client="testclient",
            source="127.0.0.1",
            settings=SETTINGS_LOGINMODE_LDAP,
            virtual="",
            file=RANDOM_STRING,
        )

    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING)
    )

    # Test for too small file
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=BASE64_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for signature with not right mode
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        mode=SignatureMode.XaDES,
        file=PDF_FILE_BASE64,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for valid signature
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=False,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        mode=SignatureMode.PaDES,
        file=PDF_FILE_BASE64,
    )

    assert all(prefix in response for prefix in ("code", "error", "message", "file"))
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == MSG_AUTH_SUCCESS
    assert re.compile(REGEX_BASE64).search(response["file"])


@pytest.mark.asyncio
async def test_list() -> None:
    """
    Test openotpList method.
    """
    # Test for too short data
    response = await openotp_soap_api.list()
    assert all(
        prefix in response for prefix in ("code", "error", "message", "jsonData")
    )
    assert response["code"] == "1"
    assert response["error"] is None
    assert response["message"] == "Authentication success"
    assert response["jsonData"] != "[]"


@pytest.mark.asyncio
async def test_check_sign() -> None:
    """
    Test openotpCheckSign method.
    """
    # Test for too short session length
    response = await openotp_soap_api.check_sign(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing session
    response = await openotp_soap_api.check_sign(RANDOM_SESSION)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "NoSession"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start an asynchronous signature
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        async_=True,
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )
    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["timeout"] == "60"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_SIGN).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)

    time.sleep(1)

    # Test for status of existing session
    response = await openotp_soap_api.check_sign(session)
    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert int(response["timeout"]) < 60
    assert response["error"] is None
    assert response["message"] == MSG_SESSION_ALREADY_STARTED
    assert re.compile(REGEX_SESSION_FORMAT).search(response["session"])


@pytest.mark.asyncio
async def test_cancel_sign() -> None:
    """
    Test openotpCancelSign method.
    """
    # Test for too short session length
    response = await openotp_soap_api.cancel_sign(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing session
    response = await openotp_soap_api.cancel_sign(RANDOM_SESSION)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "NoSession"
    assert response["code"] == "0"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start an asynchronous signature
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        domain="Default",
        async_=True,
        timeout=60,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_SIGN).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test for cancelling existing session
    response = await openotp_soap_api.cancel_sign(session)
    assert all(prefix in response for prefix in ("code", "message"))
    assert response["code"] == "1"
    assert response["message"] == MSG_MOBILE_AUTH_CANCELED


@pytest.mark.asyncio
async def test_touch_sign() -> None:
    """
    Test openotpTouchSign method.
    """
    # Test for too short session length
    response = await openotp_soap_api.touch_sign(RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing session
    response = await openotp_soap_api.touch_sign(RANDOM_SESSION)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "NoSession"
    assert response["code"] == "0"
    assert response["message"] == MSG_SESSION_NOT_STARTED

    # Start an asynchronous signature
    response = await openotp_soap_api.normal_sign(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        domain="Default",
        async_=True,
        timeout=60,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=PDF_FILE_BASE64,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "session", "timeout")
    )
    assert response["code"] == "2"
    assert response["error"] is None
    assert re.compile(REGEX_ASYNC_SIGN).search(response["message"])
    session = response["session"]
    assert re.compile(REGEX_SESSION_FORMAT).search(session)
    assert response["timeout"] == "60"

    time.sleep(1)

    # Test with existing session
    response = await openotp_soap_api.touch_sign(session)
    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "timeout", "qrImage")
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert re.compile(REGEX_ASYNC_SIGN).search(response["message"])
    assert int(response["timeout"]) < 60
    assert re.compile(REGEX_BASE64).search(response["qrImage"])


@pytest.mark.asyncio
async def test_sign_qr_code() -> None:
    """
    Test openotpSignQRCode method.
    """
    # Test for too short data
    response = await openotp_soap_api.sign_qr_code(RANDOM_STRING, RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for invalid user
    response = await openotp_soap_api.sign_qr_code(RANDOM_STRING, RANDOM_DATA)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for invalid user
    response = await openotp_soap_api.sign_qr_code(
        RANDOM_STRING, RANDOM_DATA, domain=RANDOM_STRING
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "AuthFailed"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for malformed source IP
    response = await openotp_soap_api.sign_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source=RANDOM_STRING,
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "ServerError"
    assert response["message"] == MSG_SERVER_ERROR

    # Test for file parameter not a base64 string
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await openotp_soap_api.sign_qr_code(
            f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
            RANDOM_DATA,
            domain="Default",
            timeout=60,
            issuer=RANDOM_STRING,
            client="testclient",
            source="127.0.0.1",
            settings=SETTINGS_LOGINMODE_LDAP,
            virtual="",
            file=RANDOM_STRING,
        )

    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING)
    )

    # Test for too small file
    response = await openotp_soap_api.sign_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        RANDOM_DATA,
        domain="Default",
        timeout=60,
        issuer=RANDOM_STRING,
        client="testclient",
        source="127.0.0.1",
        settings=SETTINGS_LOGINMODE_LDAP,
        virtual="",
        file=BASE64_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["code"] == "0"
    assert response["error"] == "BadRequest"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for valid signature
    response = await openotp_soap_api.sign_qr_code(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        SIGNATURE_DATA,
        domain="Default",
        mode=SignatureMode.PaDES,
        timeout=60,
        issuer="Sample Issuer",
        client="OpenOTP",
        source="127.0.0.1",
        settings="SignScope=Global",
        virtual="",
        add_cert=True,
        file=PDF_FILE_BASE64,
        qr_format=QRCodeFormat.GIF,
        qr_sizing=4,
        qr_margin=2,
    )

    assert all(
        prefix in response
        for prefix in ("code", "error", "message", "timeout", "qrImage")
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert re.compile(REGEX_ASYNC_SIGN).search(response["message"])
    assert int(response["timeout"]) <= 60
    assert re.compile(REGEX_BASE64).search(response["qrImage"])


@pytest.mark.skip("Require signature credit")
@pytest.mark.asyncio
async def test_seal() -> None:
    """
    Test openotpSeal method.
    """
    # Test for file not base64 string
    with pytest.raises(TypeError) as excinfo:
        await openotp_soap_api.seal(RANDOM_STRING)
    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("file", TYPE_BASE64_STRING)
    )

    # Test for mode not string
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await openotp_soap_api.seal(PDF_FILE_BASE64, "PADES")
    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("mode", "SignatureMode")
    )

    # Test for too small file
    response = await openotp_soap_api.seal(BASE64_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "BadRequest"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test with working parameters
    response = await openotp_soap_api.seal(
        PDF_FILE_BASE64, SignatureMode.PaDES, "testclient", "127.0.0.1", ""
    )
    assert all(prefix in response for prefix in ("code", "error", "message", "file"))
    assert response["error"] is None
    assert response["code"] == "1"
    assert response["message"] == MSG_AUTH_SUCCESS
    assert re.compile(REGEX_BASE64).search(response["file"])


@pytest.mark.asyncio
async def test_check_badging_before_badging() -> None:
    """
    Test openotpCheckBadging method.
    """
    # Test for non existing username
    response = await openotp_soap_api.check_badging(
        RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for non existing username
    response = await openotp_soap_api.check_badging(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain=RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for existing username
    response = await openotp_soap_api.check_badging(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        client="testclient",
        settings="",
        source="127.0.0.1",
        office=False,
    )

    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
        )
    )
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME


@pytest.mark.skip("Requires user interaction")
@pytest.mark.asyncio
async def test_start_badging() -> None:
    """
    Test openotpStartBadging method.
    """
    # Test for too short data
    response = await openotp_soap_api.start_badging(RANDOM_STRING, RANDOM_STRING)
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "BadRequest"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_AUTH_REQUEST

    # Test for non existing username
    response = await openotp_soap_api.start_badging(
        RANDOM_STRING,
        SIGNATURE_DATA,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for non existing username
    response = await openotp_soap_api.start_badging(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        '<![CDATA[<html style="color:white"><b>Sample Confirmation</b><br><br>Account: Example<br>Amount: XXX.XX Euros'
        "<br></html>]]>",
        domain=RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for existing username
    response = await openotp_soap_api.start_badging(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        '<![CDATA[<html style="color:white"><b>Sample Confirmation</b><br><br>Account: Example<br>Amount: XXX.XX Euros'
        "<br></html>]]>",
        domain="Default",
        client="testclient",
        settings="",
        source="127.0.0.1",
        virtual="",
    )

    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "location",
            "source",
            "address",
            "country",
        )
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert response["message"] == MSG_AUTH_SUCCESS
    assert re.compile(REGEX_COORDINATES).search(response["location"])
    assert re.compile(REGEX_IPV4).search(response["source"])
    assert re.compile(REGEX_ADDRESS).search(response["address"])
    assert response["country"] in LIST_COUNTRY_NAMES


@pytest.mark.skip("Requires user interaction")
@pytest.mark.asyncio
async def test_check_badging_after_badging() -> None:
    """
    Test openotpCheckBadging method.
    """
    # Test for non existing username
    response = await openotp_soap_api.check_badging(
        RANDOM_STRING,
    )

    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for non existing username
    response = await openotp_soap_api.check_badging(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain=RANDOM_STRING,
    )
    assert all(prefix in response for prefix in ("code", "error", "message"))
    assert response["error"] == "AuthFailed"
    assert response["code"] == "0"
    assert response["message"] == MSG_INVALID_USERNAME

    # Test for existing username
    response = await openotp_soap_api.check_badging(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1",
        domain="Default",
        client="testclient",
        settings="",
        source="127.0.0.1",
        office=False,
    )

    assert all(
        prefix in response
        for prefix in (
            "code",
            "error",
            "message",
            "location",
            "source",
            "address",
            "country",
        )
    )
    assert response["error"] is None
    assert response["code"] == "1"
    assert response["message"] == MSG_AUTH_SUCCESS
    assert re.compile(REGEX_COORDINATES).search(response["location"])
    assert re.compile(REGEX_IPV4).search(response["source"])
    assert re.compile(REGEX_ADDRESS).search(response["address"])
    assert response["country"] in LIST_COUNTRY_NAMES
