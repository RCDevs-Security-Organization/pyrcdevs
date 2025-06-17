import re
import ssl
from unittest import skipIf
import pytest

import pyrcdevs
from pyrcdevs import OpenOTPManager
from pyrcdevs.manager.OpenOTPManager import HOTPURIDigits, TOTPURIDigits
from tests.constants import (
    WEBADM_API_PASSWORD,
    WEBADM_API_USERNAME,
    WEBADM_HOST,
    REGEX_SESSION_FORMAT,
    RANDOM_STRING,
    WEBADM_BASE_DN,
    CLUSTER_TYPE,
    TESTER_NAME,
)

openotp_api_manager = OpenOTPManager(
    WEBADM_HOST,
    WEBADM_API_USERNAME,
    WEBADM_API_PASSWORD,
    443,
    verify_mode=ssl.CERT_NONE,
)


@skipIf(False, "")
@pytest.mark.asyncio
async def test_mobile_session() -> None:
    """
    Test OpenOTP.Mobile_Session method
    """

    # Test mobile session with 120 seconds of timeout
    response = await openotp_api_manager.mobile_session(120)
    assert re.compile(REGEX_SESSION_FORMAT).search(response)

    # Test mobile session with 120 seconds of timeout, and
    response = await openotp_api_manager.mobile_session(120, pincode="123456")
    assert re.compile(REGEX_SESSION_FORMAT).search(response)

    # Test with maldormed DN
    # TODO: check with devs
    response = await openotp_api_manager.mobile_session(120, dn=RANDOM_STRING)
    assert re.compile(REGEX_SESSION_FORMAT).search(response)


@skipIf(False, "")
@pytest.mark.asyncio
async def test_mobile_response() -> None:
    """
    Test OpenOTP.Mobile_Response method
    """

    # Test mobile response with a non existing session ID (must return 0)
    response = await openotp_api_manager.mobile_response(RANDOM_STRING)
    assert response == 0

    # Get a valid mobile session ID
    session_id = await openotp_api_manager.mobile_session(120)
    assert re.compile(REGEX_SESSION_FORMAT).search(session_id)

    # Test mobile response with an existing session ID (must return 2 as OpenOTP did not receive the mobile data yet)
    response = await openotp_api_manager.mobile_response(session_id)
    assert response == 2


@skipIf(False, "")
@pytest.mark.asyncio
async def test_hotp_uri() -> None:
    """
    Test OpenOTP.HOTP_URI method
    """

    cluster_type = CLUSTER_TYPE.lower()[:1]
    tester_name = TESTER_NAME.lower()[:3]
    username = f"u_{tester_name}_{cluster_type}_api_1"

    # Test with no valid inputs (we must get an exception on domain parameter)
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await openotp_api_manager.hotp_uri(
            name=RANDOM_STRING,
            key=RANDOM_STRING,
            userid=RANDOM_STRING,
            domain=RANDOM_STRING,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Domain '{RANDOM_STRING}' not existing\") tblen=3>"
    )

    # Test with only a valid input for domain parameter (we must get an exception on userid parameter)
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await openotp_api_manager.hotp_uri(
            name=RANDOM_STRING,
            key=RANDOM_STRING,
            userid=RANDOM_STRING,
            domain="Domain_Enabled",
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError('User not found Domain_Enabled\\\\{RANDOM_STRING}') tblen=3>"
    )

    # Test with a valid input for domain and userid parameters, but a key parameter not in base64 format
    # (we must get an exception on key parameter)
    with pytest.raises(pyrcdevs.manager.Manager.InvalidParams) as excinfo:
        await openotp_api_manager.hotp_uri(
            name=RANDOM_STRING,
            key="Not base64",
            userid=username,
            domain="Domain_Enabled",
        )
    assert str(excinfo) == f"<ExceptionInfo InvalidParams('Parameter key not Base64') tblen=3>"

    # Test with valid required inputs
    response = await openotp_api_manager.hotp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
    )
    assert re.compile(r"otpauth://hotp/.*").search(response)

    # Test with valid required inputs, and a wrong format for state parameter
    response = await openotp_api_manager.hotp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        state="a",
    )
    assert not response

    # Test with valid required inputs, and a valid state parameter
    response = await openotp_api_manager.hotp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        state="1",
    )
    assert re.compile(rf"otpauth://hotp/.*counter=1.*").search(response)

    # Test with valid required inputs and different sizes for digits parameter
    for hotp_uri_digit in HOTPURIDigits:
        response = await openotp_api_manager.hotp_uri(
            name=RANDOM_STRING,
            key="VmFsaWQgYmFzZTY0",
            userid=username,
            domain="Domain_Enabled",
            digits=hotp_uri_digit,
        )
        assert re.compile(rf"otpauth://hotp/.*digits={hotp_uri_digit.value}.*").search(response)

    # Test with valid inputs, tinyurl to True, but no mobile session
    response = await openotp_api_manager.hotp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        tinyurl=True,
    )
    assert not response

    # Test with valid inputs, tinyurl to True, and a non existing mobile session
    response = await openotp_api_manager.hotp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        tinyurl=True,
        session=RANDOM_STRING,
    )
    assert not response

    # Get a valid mobile session ID
    session_id = await openotp_api_manager.mobile_session(120)
    assert re.compile(REGEX_SESSION_FORMAT).search(session_id)

    # Test with valid inputs, tinyurl to True, and a valid mobile session
    response = await openotp_api_manager.hotp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        tinyurl=True,
        session=session_id,
    )
    assert response == f"https://{WEBADM_HOST}/ws/openotp/?action=qruri&session={session_id}"


@skipIf(False, "")
@pytest.mark.asyncio
async def test_totp_uri() -> None:
    """
    Test OpenOTP.TOTP_URI method
    """

    cluster_type = CLUSTER_TYPE.lower()[:1]
    tester_name = TESTER_NAME.lower()[:3]
    username = f"u_{tester_name}_{cluster_type}_api_1"

    # Test with no valid inputs (we must get an exception on domain parameter)
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await openotp_api_manager.totp_uri(
            name=RANDOM_STRING,
            key=RANDOM_STRING,
            userid=RANDOM_STRING,
            domain=RANDOM_STRING,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Domain '{RANDOM_STRING}' not existing\") tblen=3>"
    )

    # Test with only a valid input for domain parameter (we must get an exception on userid parameter)
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await openotp_api_manager.totp_uri(
            name=RANDOM_STRING,
            key=RANDOM_STRING,
            userid=RANDOM_STRING,
            domain="Domain_Enabled",
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError('User not found Domain_Enabled\\\\{RANDOM_STRING}') tblen=3>"
    )

    # Test with a valid input for domain and userid parameters, but a key parameter not in base64 format
    # (we must get an exception on key parameter)
    with pytest.raises(pyrcdevs.manager.Manager.InvalidParams) as excinfo:
        await openotp_api_manager.totp_uri(
            name=RANDOM_STRING,
            key="Not base64",
            userid=username,
            domain="Domain_Enabled",
        )
    assert str(excinfo) == f"<ExceptionInfo InvalidParams('Parameter key not Base64') tblen=3>"

    # Test with valid required inputs
    response = await openotp_api_manager.totp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
    )
    assert re.compile(r"otpauth://totp/.*").search(response)

    # Test with valid required inputs, and a wrong period
    response = await openotp_api_manager.totp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        period=1,
    )
    assert not response

    # Test with valid required inputs, and a right period
    response = await openotp_api_manager.totp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        period=30,
    )
    assert re.compile(r"otpauth://totp/.*period=30.*").search(response)

    # Test with valid required inputs and different sizes for digits parameter
    for totp_uri_digit in TOTPURIDigits:
        response = await openotp_api_manager.totp_uri(
            name=RANDOM_STRING,
            key="VmFsaWQgYmFzZTY0",
            userid=username,
            domain="Domain_Enabled",
            digits=totp_uri_digit,
        )
        assert re.compile(rf"otpauth://totp/.*digits={totp_uri_digit.value}.*").search(response)

    # Test with valid inputs, tinyurl to True, but no mobile session
    response = await openotp_api_manager.totp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        tinyurl=True,
    )
    assert not response

    # Test with valid inputs, tinyurl to True, and a non existing mobile session
    response = await openotp_api_manager.totp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        tinyurl=True,
        session=RANDOM_STRING,
    )
    assert not response

    # Get a valid mobile session ID
    session_id = await openotp_api_manager.mobile_session(120)
    assert re.compile(REGEX_SESSION_FORMAT).search(session_id)

    # Test with valid inputs, tinyurl to True, and a valid mobile session
    response = await openotp_api_manager.totp_uri(
        name=RANDOM_STRING,
        key="VmFsaWQgYmFzZTY0",
        userid=username,
        domain="Domain_Enabled",
        tinyurl=True,
        session=session_id,
    )
    assert response == f"https://{WEBADM_HOST}/ws/openotp/?action=qruri&session={session_id}"


@skipIf(False, "")
@pytest.mark.asyncio
async def test_domain_report() -> None:
    """
    Test OpenOTP.Domain_Report method
    """

    api_base_dn = WEBADM_BASE_DN.lower()
    base_dn = api_base_dn.replace("ou=pyrcdevs,", "")
    cluster_type = CLUSTER_TYPE.lower()[:1]
    tester_name = TESTER_NAME.lower()[:3]

    response = await openotp_api_manager.domain_report(RANDOM_STRING)
    assert not response

    response = await openotp_api_manager.domain_report("Domain_Enabled")
    assert isinstance(response, dict)
    objects = list(response.keys())
    objects.sort()
    expected_list = []
    for user in ["api_1", "api_4"] + (
        ["api_2", "api_3", "unact"] if CLUSTER_TYPE.lower() == "metadata" else []
    ):
        expected_list.append(f"cn=u_{tester_name}_{cluster_type}_{user},{api_base_dn}")
    for user in [
        "cp_allowed",
        "cp_excluded",
        "cp_layer1",
        "cp_layer2",
        "cp_layer3",
        "cp_layer4",
        "cp_layer5",
        "cp_layer6",
        "cp_layer7",
        "dom_allowed",
        "dom_excluded",
        "eap",
        "explicit",
        "friend-alias",
        "helpdesk",
        "implicit",
        "ldproxy",
        "mobile",
        "openid",
        "pam",
        "radiusd",
        "saml",
    ]:
        if CLUSTER_TYPE.lower() == "mssp":
            expected_list.append(f"cn=u_{user},{base_dn}")
        else:
            expected_list.append(f"cn=u_{tester_name}_{cluster_type}_{user},{base_dn}")
    expected_list.sort()
    assert [item.lower() for item in objects] == expected_list

    response = await openotp_api_manager.domain_report("Domain_Enabled", token=True)
    assert isinstance(response, dict)
    objects = list(response.keys())
    objects.sort()
    assert [item.lower() for item in objects] == expected_list
