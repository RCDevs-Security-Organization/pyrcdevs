import re
import ssl
from unittest import skipIf

import pytest

from pyrcdevs import OpenOTPManager
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
    for user in ["api_1", "api_4"]:
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
        expected_list.append(f"cn=u_{tester_name}_{cluster_type}_{user},{base_dn}")
    expected_list.sort()
    assert [item.lower() for item in objects] == expected_list
