import asyncio
import re
import ssl
from unittest import skipIf

from pyrcdevs import OpenOTPManager
from tests.constants import (
    WEBADM_API_PASSWORD,
    WEBADM_API_USERNAME,
    WEBADM_HOST,
    REGEX_SESSION_FORMAT,
    RANDOM_STRING,
    WEBADM_BASE_DN,
)

openotp_api_manager = OpenOTPManager(
    WEBADM_HOST, WEBADM_API_USERNAME, WEBADM_API_PASSWORD, 443, verify_mode=ssl.CERT_NONE
)


@skipIf(True, "")
def test_mobile_session() -> None:
    """
    Test OpenOTP.Mobile_Session method
    """

    # Test mobile session with 120 seconds of timeout
    response = asyncio.run(openotp_api_manager.mobile_session(120))
    assert re.compile(REGEX_SESSION_FORMAT).search(response)

    # Test mobile session with 120 seconds of timeout, and
    response = asyncio.run(openotp_api_manager.mobile_session(120, pincode="123456"))
    assert re.compile(REGEX_SESSION_FORMAT).search(response)

    # Test with maldormed DN
    # TODO: check with devs
    response = asyncio.run(openotp_api_manager.mobile_session(120, dn=RANDOM_STRING))
    assert re.compile(REGEX_SESSION_FORMAT).search(response)


@skipIf(True, "")
def test_domain_report() -> None:
    """
    Test OpenOTP.Domain_Report method
    """

    response = asyncio.run(openotp_api_manager.domain_report(RANDOM_STRING))
    assert not response

    response = asyncio.run(openotp_api_manager.domain_report("Domain_Enabled"))
    assert isinstance(response, dict)
    objects = list(response.keys())
    objects.sort()
    assert objects == [
        f"cn=u_ben_m_api_1,ou=pyrcdevs,{WEBADM_BASE_DN}",
        f"cn=u_ben_m_api_4,ou=pyrcdevs,{WEBADM_BASE_DN}",
        f"cn=u_cp_allowed,{WEBADM_BASE_DN}",
        f"cn=u_cp_excluded,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer1,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer2,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer3,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer4,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer5,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer6,{WEBADM_BASE_DN}",
        f"cn=u_cp_layer7,{WEBADM_BASE_DN}",
        f"cn=u_dom_allowed,{WEBADM_BASE_DN}",
        f"cn=u_dom_excluded,{WEBADM_BASE_DN}",
        f"cn=u_eap,{WEBADM_BASE_DN}",
        f"cn=u_explicit,{WEBADM_BASE_DN}",
        f"cn=u_friend-alias,{WEBADM_BASE_DN}",
        f"cn=u_helpdesk,{WEBADM_BASE_DN}",
        f"cn=u_implicit,{WEBADM_BASE_DN}",
        f"cn=u_ldproxy,{WEBADM_BASE_DN}",
        f"cn=u_mobile,{WEBADM_BASE_DN}",
        f"cn=u_openid,{WEBADM_BASE_DN}",
        f"cn=u_pam,{WEBADM_BASE_DN}",
        f"cn=u_radiusd,{WEBADM_BASE_DN}",
        f"cn=u_saml,{WEBADM_BASE_DN}",
    ]
