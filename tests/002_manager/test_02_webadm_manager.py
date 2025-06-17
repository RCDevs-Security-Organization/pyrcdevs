"""This module implements tests for WebADM API Manager."""

import base64
import email
import hashlib
import imaplib
import json
import locale
import re
import secrets
import ssl
import time
from datetime import datetime, timedelta
from email.message import Message
from enum import Enum
from io import BytesIO
from typing import Tuple
from unittest import skipIf

import pytest
import pytz
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from PIL import Image
from requests import Session
from requests.adapters import HTTPAdapter

import pyrcdevs
from M2Crypto import SMIME, BIO
from pyrcdevs import WebADMManager
from pyrcdevs.constants import MSG_NOT_RIGHT_TYPE, REGEX_BASE64
from pyrcdevs.manager import InternalError
from pyrcdevs.manager.Manager import InvalidParams
from pyrcdevs.manager.WebADMManager import (
    AutoConfirmApplication,
    AutoConfirmExpiration,
    ClientMode,
    ConfigObjectApplication,
    ConfigObjectType,
    EventLogApplication,
    InventoryStatus,
    LDAPSearchScope,
    LDAPSyncObjectType,
    LicenseProduct,
    QRCodeFormat,
    QRCodeMargin,
    QRCodeSize,
    UnlockApplication,
)
from tests.constants import (
    CA_CERT_PATH,
    CLUSTER_TYPE,
    DEFAULT_PASSWORD,
    DICT_USER_OBJECTCLASS,
    EXCEPTION_NOT_RIGHT_TYPE,
    GROUP_OBJECTCLASS,
    LDAP_BASE_DN,
    LIST_STATUS_SERVERS_KEYS,
    LIST_STATUS_WEB_TYPES,
    LIST_USER_ACCOUNT_LDAP_AD,
    LIST_USER_ACCOUNT_LDAP_SLAPD,
    MAILSERVER,
    OPENOTP_PUSHID,
    OPENOTP_TOKENKEY,
    RANDOM_STRING,
    REGEX_LOGTIME_TIME,
    REGEX_PARAMETER_DN_NOT_STRING,
    REGEX_VERSION_NUMBER,
    SMS_MOBILE,
    TESTER_NAME,
    USER_CERT_PATH,
    WEBADM_API_PASSWORD,
    WEBADM_API_USERNAME,
    WEBADM_BASE_DN,
    WEBADM_HOST,
)

webadm_api_manager = WebADMManager(
    WEBADM_HOST,
    WEBADM_API_USERNAME,
    WEBADM_API_PASSWORD,
    443,
    verify_mode=ssl.CERT_NONE,
)

uid_numbers = {}


class BadgingAction(Enum):
    """An enumeration class to detail possible badging actions"""

    IN = "in"
    OUT = "out"


class HostHeaderSSLAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)


def get_email_body(message: Message, encoding: str = "utf-8") -> list:
    body_parts = []
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            content_attachment = part.get_payload(decode=True)
            if content_type != "multipart/mixed":
                body_parts.append(
                    {
                        "content_type": content_type,
                        "content_disposition": content_disposition,
                        "content_attachment": content_attachment,
                    }
                )
    else:
        content_type = message.get_content_type()
        content_disposition = message.get_content_disposition()
        content_attachment = message.get_payload(decode=True).decode(encoding)
        body_parts.append(
            {
                "content_type": content_type,
                "content_disposition": content_disposition,
                "content_attachment": content_attachment,
            }
        )
    return body_parts


def get_mailbox_content(email_address: str):
    with imaplib.IMAP4(MAILSERVER) as mailserver:
        try:
            status, messages = mailserver.login(email_address, "password")
        except imaplib.IMAP4.error as imap_err:
            print(f"Issue authenticating to email account ({email}): {str(imap_err)}")
            return []
        if status != "OK":
            print(f"Issue authenticating to email account ({email}): {messages}")
            return []
        status, messages = mailserver.select("Inbox")
        if status != "OK":
            msg_details = b"\n".join(messages).decode()
            print(
                f"Issue selecting Inbox mailbox for email account ({email}):\n{msg_details}"
            )
            return []
        status, messages = mailserver.search(None, "ALL")
        if status != "OK":
            return []
        mails = []
        for num in messages[0].split():
            status, data = mailserver.fetch(num, "(RFC822)")
            if status != "OK":
                continue
            # noinspection PyUnresolvedReferences
            message = email.message_from_bytes(data[0][1])
            sender = message["From"]
            to = message["To"]
            body = get_email_body(message)
            subject = message["Subject"]
            date = message["Date"]
            locale.setlocale(locale.LC_TIME, "en_US.UTF-8")
            utc_timezone = pytz.timezone("Etc/UTC")
            date_time = datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %z")
            date_time_utc = date_time.astimezone(utc_timezone)
            otps = []
            body_plain_text = [
                a["content_attachment"]
                for a in body
                if a["content_type"] == "text/plain"
            ]
            if "Login" in subject:
                otps = re.findall(r"(\d{6})", " ".join(body_plain_text))
            self_links = []
            if "Self-Registration" in subject:
                self_links = re.findall(
                    r"(https://.*/webapps/selfreg[^.]*)\.", " ".join(body_plain_text)
                )
            mail = {
                "Date": date_time_utc,
                "From": sender,
                "To": to,
                "subject": subject,
                "body": body,
            }
            if len(otps) > 0:
                mail["otps"] = otps
            if len(self_links) > 0:
                mail["self_links"] = self_links
            mails.append(mail)
    return mails


def get_otp_and_email_body(
    email_address: str, formatted_utc_now: datetime
) -> Tuple[str, list]:
    """
    Return body and list of possible OTPs from first mailbox email having an older date than formatted_utc_now
    :param str email_address: email address of mailbox
    :param datetime.datetime formatted_utc_now:
    :rtype Tuple[str, list]
    :return: Tuple of body and list of possible OTPs
    """
    possible_otps = []
    body = ""
    email_messages = get_mailbox_content(email_address)
    for message in email_messages:
        message_date = message.get("Date")
        if message_date > formatted_utc_now and "otps" in message:
            possible_otps = message.get("otps")
            body = message.get("body")
            break
    return body, possible_otps


def get_random_uid_number():
    list_uid_numbers = list(uid_numbers.values())
    random_uid_number = 600 + secrets.randbits(10)
    while random_uid_number in list_uid_numbers:
        random_uid_number = 600 + secrets.randbits(10)
    return random_uid_number


def webbadge(
    host: str,
    username: str,
    password: str,
    domain: str,
    action: BadgingAction = BadgingAction.IN,
    ip: str = None,
    x_forwarded_for: str = None,
) -> bool:
    """
    Badge in or badge out a user using Self-Desk webapp.

    Using requests library, authenticate to the Self-Desk using given host, credentials,
    then, do a badge out or badge in action, depending on given action.
    :param str host: host name of WebADM
    :param str username: account username
    :param str password: account password
    :param str domain: domain of account
    :param BadgingAction action: badging action (default to BadgingAction.IN)
    :param str ip: IP of SelfDesk applicaton (default to None).
    :param str x_forwarded_for: X-Forwarded-For HTTP header value, which can be used to simulate a public IP (default
    to None)
    :return: boolean of badging action result
    :rtype: bool
    """
    try:
        if ip is None:
            endpoint_host = host
        else:
            endpoint_host = ip

        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED

        with Session() as s:
            s.mount("https://", HostHeaderSSLAdapter(context))
            s.headers.update({"Host": host})
            if x_forwarded_for is not None:
                s.headers["X-Forwarded-For"] = f"{x_forwarded_for}, 10.211.0.1"

            s.get(
                url=f"https://{endpoint_host}/webapps/selfdesk/login_uid.php",
                verify=CA_CERT_PATH,
                allow_redirects=True,
            )
            auth_resp = s.post(
                url=f"https://{endpoint_host}/webapps/selfdesk/login_uid.php",
                verify=CA_CERT_PATH,
                data={
                    "login": 1,
                    "username": username,
                    "password": password,
                    "domain": domain,
                },
            )

            if auth_resp.status_code != 200:
                print(
                    f"Issue authenticating to Self-Desk. HTTP return code is {auth_resp.status_code}!"
                )
                return False

            tokens = re.findall(r"'index\.php\?token=([^']*)'", auth_resp.text)

            if len(tokens) != 1:
                print("Issue authenticating to Self-Desk: cannot get a token!")
                return False

            token = tokens[0]

            badging_resp = s.get(
                url=f"https://{endpoint_host}/webapps/selfdesk/badging.php?action={action.value}&token={token}",
                verify=CA_CERT_PATH,
            )

            successes = re.findall(r"(Successfully badged )", badging_resp.text)

            return len(successes) == 1
    except requests.exceptions.ConnectionError as conn_error:
        print(str(conn_error))
        return False


async def _test_malformed_dns(method, pos, *args) -> None:
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        arguments = tuple(list(args[: pos - 1]) + [1] + list(args[pos - 1 :]))
        # noinspection PyTypeChecker
        await method(*arguments)
        # NOSONAR
    assert str(excinfo).startswith(REGEX_PARAMETER_DN_NOT_STRING)

    # Test to non existing DN
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        arguments = tuple(
            list(args[: pos - 1])
            + [f"CN=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}"]
            + list(args[pos - 1 :])
        )
        await method(*arguments)
    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"LDAP object 'CN=Not_exist_{RANDOM_STRING},o=root' does not exist\")"
    ) or str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"LDAP object 'CN=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}' does not exist\")"
    )

    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        arguments = tuple(
            list(args[: pos - 1]) + [RANDOM_STRING] + list(args[pos - 1 :])
        )
        await method(*arguments)
    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\")"
    ) or str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
        f"NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of:"
        f"\\t'{RANDOM_STRING}')\")"
    )


def generate_user_attrs(username: str, gid_number: int = None) -> dict:
    """
    This method creates and returns a dictionary of user attributes
    :param str username: username of account
    :param int gid_number: GID number of account for posixaccount objectclass
    :return: a dictionary of user attributes
    :rtype: dict
    """
    user_attributes = {
        "objectclass": ["person", "inetorgperson"],
        "sn": username,
        "cn": username,
    }
    if CLUSTER_TYPE == "mssp":
        user_attributes["uid"] = username
    else:
        user_attributes["samaccountname"] = username
    if gid_number is not None:
        random_uid_number = get_random_uid_number()
        uid_numbers[username] = random_uid_number
        # noinspection PyUnresolvedReferences
        user_attributes["objectclass"].append("posixAccount")
        user_attributes["uidnumber"] = random_uid_number
        user_attributes["gidnumber"] = gid_number
        user_attributes["homedirectory"] = f"/home/{username}"
        user_attributes["loginshell"] = "/bin/bash"

    if GROUP_OBJECTCLASS == "group":
        user_attributes["useraccountcontrol"] = "512"
        user_attributes["unicodePwd"] = DEFAULT_PASSWORD
        user_attributes["samaccountname"] = username
    else:
        user_attributes["userpassword"] = (
            "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y"  # NOSONAR
        )
    return user_attributes


def generate_group_attrs(groupname: str, gid_number: int) -> dict:
    """
    This method creates and returns a dictionary of group attributes
    :param str groupname: name of group
    :param int gid_number: GID number of group for posixgroup objectclass
    :return: a dictionary of group attributes
    :rtype: dict
    """
    group_attributes = {
        "objectclass": [GROUP_OBJECTCLASS, "posixgroup"],
        "cn": groupname,
        "gidnumber": gid_number,
    }
    if GROUP_OBJECTCLASS == "group":
        group_attributes["samaccountname"] = groupname
    return group_attributes


@pytest.mark.asyncio
async def test_create_ldap_object() -> None:
    """
    Test Create_LDAP_Object method
    """
    # Test creating object with malformed DN
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.create_ldap_object(
            RANDOM_STRING,
            {
                "objectclass": ["person", "inetorgperson"],
                "sn": "testfail",
                "cn": "testfail",
                "uid": "testfail",
                "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
            },
        )

    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\")"
    ) or str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' "
        f"(0000208F: NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match "
        f"of:\\t'{RANDOM_STRING}')\")"
    )

    # Test creating object in non existing container
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.create_ldap_object(
            f"CN=testfail,OU={RANDOM_STRING},{WEBADM_BASE_DN}",
            {
                "objectclass": ["person", "inetorgperson"],
                "sn": "testfail",
                "cn": "testfail",
                "uid": "testfail",
                "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
            },
        )

    assert (
        str(excinfo).startswith(
            f"<ExceptionInfo InternalError(\"Could not create LDAP object 'CN=testfail,OU={RANDOM_STRING},"
            f"{WEBADM_BASE_DN}' (No such object)\")"
        )
        or str(excinfo).startswith(
            f"<ExceptionInfo InternalError(\"Could not create LDAP object 'CN=testfail,OU={RANDOM_STRING},"
            f"{WEBADM_BASE_DN[:47]}..., data 0, best match of:\\t'{LDAP_BASE_DN}')\")"
        )
        or str(excinfo.value)
        == f"Could not create LDAP object 'CN=testfail,OU={RANDOM_STRING},{WEBADM_BASE_DN}' "
        f"(0000208D: NameErr: DSID-0310028D, problem 2001 (NO_OBJECT), data 0, best match "
        f"of:\t'{LDAP_BASE_DN}')"
    )

    # Test creating testfail object with no attribute information
    response = await webadm_api_manager.create_ldap_object(
        f"CN=testfail,{WEBADM_BASE_DN}",
        {},
    )
    assert not response

    # Test creating testuserapi1 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", 100
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi2 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2", 100
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi3 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3"
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi4 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4"
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating api_5 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5"
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating again testuserapi1 object
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        user_attributes = generate_user_attrs(f"u_{CLUSTER_TYPE}_api_1", 100)
        await webadm_api_manager.create_ldap_object(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
            user_attributes,
        )
    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"LDAP object 'CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,"
        f"{WEBADM_BASE_DN}' already exist\")"
    )

    # Test creating unactivated object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact"
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testgroup1 object
    group_attributes = generate_group_attrs(
        f"g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", 100
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        group_attributes,
    )
    assert response

    # Test creating testgroup2 object
    group_attributes = generate_group_attrs(
        f"g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2", 101
    )
    response = await webadm_api_manager.create_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}",
        group_attributes,
    )
    assert response

    with open("/tmp/uidnumbers.json", "w") as json_file:
        json_file.write(json.dumps(uid_numbers))

    # Test creating new_ou OU
    response = await webadm_api_manager.create_ldap_object(
        f"ou=new_ou,{WEBADM_BASE_DN}",
        {"objectclass": ["organizationalunit"], "ou": "new_ou"},
    )
    assert response


@pytest.mark.asyncio
async def test_activate_ldap_object() -> None:
    """
    Test Activate_LDAP_Object method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.activate_ldap_object, 1)

    # Test to activate existing account
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )

    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
    )

    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}"
    )

    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account already activated
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )

    assert not response

    # Test to activate existing group
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )

    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing group
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}"
    )

    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing group already activated
    response = await webadm_api_manager.activate_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )

    assert not response


@pytest.mark.asyncio
async def test_deactivate_ldap_object() -> None:
    """
    Test Deactivate_LDAP_Object method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.deactivate_ldap_object, 1)

    # Test to deactivate an activated account
    response = await webadm_api_manager.deactivate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
    )

    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    if "metadata" not in WEBADM_HOST:
        with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
            await webadm_api_manager.deactivate_ldap_object(
                f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
            )

        assert str(excinfo).startswith(
            f"<ExceptionInfo InternalError(\"Object 'CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,"
            f"{WEBADM_BASE_DN}' is not an activated user or group\")"
        )


@pytest.mark.asyncio
async def test_cert_auto_confirm() -> None:
    """
    Test Cert_Auto_Confirm method.
    """
    # Test with bad type for expires argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.cert_auto_confirm(1, AutoConfirmApplication.OPENOTP)
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('application type is not AutoConfirmExpiration')"
    )

    # Test with bad type for application argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.cert_auto_confirm(AutoConfirmExpiration.E1, "OpenOTP")
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('application type is not AutoConfirmApplication')"
    )

    # Test with bad type for addresses argument.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.cert_auto_confirm(
            AutoConfirmExpiration.E1, addresses=1
        )
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo InvalidParams('Parameter addresses not String')"
    )

    # Test setting 10 minutes for expires and a bad address format for addresses
    with pytest.raises(InternalError) as excinfo:
        await webadm_api_manager.cert_auto_confirm(
            AutoConfirmExpiration.E10, addresses="bad address format"
        )

    assert str(excinfo).startswith(
        "<ExceptionInfo InternalError('Invalid IP address or mask')"
    )

    # Test setting 1 minute for expires
    cert_auto_confirm_response = await webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E1
    )

    assert cert_auto_confirm_response

    # Test setting 10 minutes for expires, and OpenOTP as application
    cert_auto_confirm_response = await webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E10, AutoConfirmApplication.OPENOTP
    )

    assert cert_auto_confirm_response

    # Test setting 10 minutes for expires, and 127.0.0.1/24 for addresses
    cert_auto_confirm_response = await webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E10, addresses="127.0.0.1/24"
    )

    assert cert_auto_confirm_response

    # Test setting 10 minutes for expires, OpenOTP for application, and 127.0.0.1/24 for addresses
    cert_auto_confirm_response = await webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E10,
        application=AutoConfirmApplication.OPENOTP,
        addresses="127.0.0.1/24",
    )

    assert cert_auto_confirm_response


@pytest.mark.asyncio
async def test_check_ldap_object() -> None:
    """
    Test Check_LDAP_Object method.
    """
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.check_ldap_object(1)
        # NOSONAR
    assert str(excinfo).startswith(REGEX_PARAMETER_DN_NOT_STRING)

    # Test with malformed DN.
    with pytest.raises(InternalError) as excinfo:
        await webadm_api_manager.check_ldap_object(RANDOM_STRING)
    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\")"
    ) or str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
        "NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of"
        f":\\t'{RANDOM_STRING}')\")"
    )

    # Test with non existing DN object
    check_ldap_object_response = await webadm_api_manager.check_ldap_object(
        f"CN={RANDOM_STRING},{WEBADM_BASE_DN}"
    )

    assert not check_ldap_object_response

    # Test with existing DN object
    check_ldap_object_response = await webadm_api_manager.check_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )

    assert check_ldap_object_response


@pytest.mark.asyncio
async def test_check_user_active() -> None:
    """
    Test Check_User_Active method.
    """
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.check_user_active(1)
        # NOSONAR
    assert str(excinfo).startswith(REGEX_PARAMETER_DN_NOT_STRING)

    if "metadata" not in WEBADM_HOST:
        # Test with malformed DN.
        with pytest.raises(InternalError) as excinfo:
            await webadm_api_manager.check_user_active(RANDOM_STRING)
        assert str(excinfo).startswith(
            f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\")"
        ) or str(excinfo).startswith(
            f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
            "NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of"
            f":\\t'{RANDOM_STRING}')\")"
        )

        # Test with non existing DN object
        with pytest.raises(InternalError) as excinfo:
            await webadm_api_manager.check_user_active(
                f"CN={RANDOM_STRING},{WEBADM_BASE_DN}"
            )

        assert (
            f"<ExceptionInfo InternalError(\"Could not read LDAP object 'CN={RANDOM_STRING},"
            in str(excinfo)
        )

        # Test with existing activated user object (testuserapi1)
        response = await webadm_api_manager.check_user_active(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
        )

        assert response

        # Test with existing unactivated user object (unactivated)
        response = await webadm_api_manager.check_user_active(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}"
        )

        assert not response


@pytest.mark.asyncio
async def test_check_user_password() -> None:
    """
    Test Check_User_Password method.
    """
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.check_user_password(1, "")
        # NOSONAR
    assert str(excinfo).startswith(REGEX_PARAMETER_DN_NOT_STRING)

    # Test with wrong password type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.check_user_password(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}", 1
        )

        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo InvalidParams('Parameter password not String')"
    )

    # Test with malformed DN.
    with pytest.raises(InternalError) as excinfo:
        await webadm_api_manager.check_user_password(RANDOM_STRING, DEFAULT_PASSWORD)

    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\")"
    ) or str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' "
        f"(0000208F: NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match "
        f"of:\\t'{RANDOM_STRING}')\")"
    )

    # Test with non existing DN object
    with pytest.raises(InternalError) as excinfo:
        await webadm_api_manager.check_user_password(
            f"CN={RANDOM_STRING},{WEBADM_BASE_DN}",
            DEFAULT_PASSWORD,
        )

    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"LDAP object 'CN={RANDOM_STRING},{WEBADM_BASE_DN}' "
        f'does not exist")'
    )

    # Test with existing DN object, but a wrong password
    check_user_password_response = await webadm_api_manager.check_user_password(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        "wrong password",
    )

    assert not check_user_password_response

    # Test with existing DN object, and the right password
    check_user_password_response = await webadm_api_manager.check_user_password(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        DEFAULT_PASSWORD,
    )

    assert check_user_password_response


@pytest.mark.asyncio
async def test_clear_caches() -> None:
    """
    Test Clear_Caches method.
    """
    # Test with no argument provided.
    clear_caches_response = await webadm_api_manager.clear_caches()
    assert clear_caches_response

    # Test with wrong type_ type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.clear_caches(1, 1)  # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo InvalidParams('Parameter type not String')"
    )

    # Test with wrong tenant type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.clear_caches("test", 1)  # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo InvalidParams('Parameter tenant not String')"
    )

    # Test with non existing type_.
    clear_caches_response = await webadm_api_manager.clear_caches("nonexistingtype")
    # NOSONAR
    assert not clear_caches_response

    for type_str in [
        "config",
        "adminrole",
        "domain",
        "client",
        "optionset",
        "tenant",
        "mountpoint",
        "webapp",
        "websrv",
        "cacert",
        "admgrp",
        "appmsg",
        "lcache",
    ]:
        clear_caches_response = await webadm_api_manager.clear_caches(type_str)
        # NOSONAR
        assert clear_caches_response


@pytest.mark.asyncio
async def test_server_status() -> None:
    """
    Test Server_Status method.
    """
    # Test with no argument provided. It must return only general status and version.
    server_status_response = await webadm_api_manager.server_status()
    keys = list(server_status_response.keys())
    keys.sort()
    assert keys == ["status", "version"]
    assert isinstance(server_status_response["status"], bool)
    assert re.compile(REGEX_VERSION_NUMBER).search(server_status_response["version"])

    # Test with all arguments provided (all set to False). It must also return only general status and version.
    server_status_response = await webadm_api_manager.server_status(False, False, False)

    keys = list(server_status_response.keys())
    keys.sort()
    assert keys == ["status", "version"]
    assert isinstance(server_status_response["status"], bool)
    assert re.compile(REGEX_VERSION_NUMBER).search(server_status_response["version"])

    # Test with all arguments provided (set to True). It must return general status and version,
    # and status of servers, webapps, and websrvs.
    server_status_response = await webadm_api_manager.server_status(True, True, True)

    keys = list(server_status_response.keys())
    keys.sort()

    assert keys == ["servers", "status", "version", "webapps", "websrvs"]

    assert isinstance(server_status_response["status"], bool)

    assert re.compile(REGEX_VERSION_NUMBER).search(server_status_response["version"])

    servers = server_status_response["servers"]
    servers_keys = list(servers.keys())
    servers_keys.sort()
    assert servers_keys == LIST_STATUS_SERVERS_KEYS
    for servers_key in LIST_STATUS_SERVERS_KEYS:
        assert isinstance(server_status_response["servers"][servers_key], bool)

    # Contents of webapps and websrvs statuses are tested below
    # Each type must contain a dictionary with specific keys (see LIST_STATUS_WEB_TYPES constant).
    for web_type in LIST_STATUS_WEB_TYPES:
        web_type_value = server_status_response[web_type]
        assert isinstance(web_type_value, dict)
        web_type_value_keys = list(web_type_value.keys())
        web_type_value_keys.sort()
        assert web_type_value_keys == LIST_STATUS_WEB_TYPES[web_type]

        # The value of each of these keys must be a dictionary and contains the following keys
        # - ["status", "version"] for webapps
        # - ["licence", "status", "version"] for websrvs
        # The value of the version key must, of course, contain a version number.
        # The values of the status and licence keys must be either Ok or Invalid.
        for web_type_sub_key in LIST_STATUS_WEB_TYPES[web_type]:
            web_type_sub_key_value = server_status_response[web_type][web_type_sub_key]
            assert isinstance(web_type_sub_key_value, dict)
            web_type_sub_key_value_keys = list(web_type_sub_key_value.keys())
            web_type_sub_key_value_keys.sort()
            assert (
                web_type_sub_key_value_keys == ["status", "version"]
                if web_type == "webapps"
                else ["license", "status", "version"]
            )
            assert re.compile(REGEX_VERSION_NUMBER).search(
                server_status_response[web_type][web_type_sub_key]["version"]
            )
            assert server_status_response[web_type][web_type_sub_key]["status"] in [
                "Ok",
                "Invalid",
            ]
            if "license" in web_type_sub_key_value_keys:
                assert server_status_response[web_type][web_type_sub_key][
                    "license"
                ] in [
                    "Ok",
                    "Invalid",
                ]


@pytest.mark.asyncio
async def test_set_user_data() -> None:
    """
    Test Set_User_Data method.
    """
    response = await webadm_api_manager.set_user_data(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        {
            "OpenOTP.EmergOTP": "4QrcOUm6Wau+VuBX8g+IPmZy2wOXWf+aAAA=",
            "SpanKey.PublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6UxOwHGPE0+O3bxOV64XNzmKPZTvW6O8zhxi"
            "gi/3"
            "L2vWvLKyY0W9A5aSmSGffL+2+NotXjRYHOg7Tz/Dx6gXP8sJzUzsVxWo9hSKorajpS6Cvs+XD1ae5p7quU25Q"
            "xRcVz3h+kpPxAIXhQpGDMmfrtpIRCdCO/1y4uri6jKZALY87XcKPFauVCcxSkrg37QILeBU7LhsHRJCRlkLAu"
            "hJ6rtrig1soCqYrH0Vw779rZBXbQNbKVuMFbmG3PmCbs5m/jC29Z0aQMEVs4DhETxBqyqSaqCSdqfI7WGrOjh"
            "L6RvtYAHnc2xjlijV6phOxicvwMt9Q9x9CKXEDyo5B6DNwIDAQAB",
            "SpanKey.KeyType": "c3NoLXJzYQ==",
            "OpenOTP.TokenType": "VE9UUA==",
            "OpenOTP.TokenKey": OPENOTP_TOKENKEY,
            "OpenOTP.TokenState": "MA==",
            "OpenOTP.TokenSerial": "MGEwZTI2MjgxYmRmOWYwOA==",
            "OpenOTP.TokenModel": "TW9iaWxlIHBob25l",
            "OpenOTP.TokenID": OPENOTP_PUSHID,
        },
    )

    assert response


@pytest.mark.asyncio
async def test_count_activated_hosts() -> None:
    """
    Test Count_Activated_Hosts method.
    """
    # Test with wrong type for product parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.count_activated_hosts("OpenOTP")
    assert str(excinfo).startswith(
        f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('product', 'LicenseProduct')}')"
    )

    # Test with no parameter
    response = await webadm_api_manager.count_activated_hosts()
    assert isinstance(response, int) and response >= 0

    # Test with parameter set to LicenseProduct.OPENOTP
    response = await webadm_api_manager.count_activated_hosts(LicenseProduct.OPENOTP)

    assert isinstance(response, int) and response >= 0


@pytest.mark.asyncio
async def test_count_activated_users() -> None:
    """
    Test Count_Activated_Users method.
    """
    # Test with wrong type for product parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.count_activated_users("OpenOTP")
    assert str(excinfo).startswith(
        f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('product', 'LicenseProduct')}')"
    )

    # Test with no parameter
    response = await webadm_api_manager.count_activated_users()
    assert isinstance(response, int) and response >= 0

    # Test with parameter set to LicenseProduct.OPENOTP
    response = await webadm_api_manager.count_activated_users(LicenseProduct.OPENOTP)

    assert isinstance(response, int) and response >= 0


@pytest.mark.asyncio
async def test_count_domain_users() -> None:
    """
    Test Count_Domain_Users method.
    """
    # Test with unknown domain
    response = await webadm_api_manager.count_domain_users(RANDOM_STRING)
    assert not response

    # Test with existing domain
    all_users = await webadm_api_manager.count_domain_users("Default")
    assert isinstance(all_users, int) and all_users >= 0

    # Test with existing domain and explicitly requesting all users
    all_users2 = await webadm_api_manager.count_domain_users("Default", False)
    assert isinstance(all_users2, int) and all_users == all_users2

    # Test with existing domain and requesting only activated users
    activated_users = await webadm_api_manager.count_domain_users("Default", True)

    assert (
        isinstance(activated_users, int)
        and activated_users >= 0
        and (
            activated_users != all_users
            or ("metadata" in WEBADM_HOST and activated_users == all_users)
        )
    )


@pytest.mark.asyncio
async def test_set_user_attrs() -> None:
    """
    Test Set_User_Attrs method.
    """
    with open(USER_CERT_PATH, "rb") as user_cert_file:
        user_cert = user_cert_file.read()
    response = await webadm_api_manager.set_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        {
            "usercertificate": [
                repr(user_cert.decode())
                .replace("\\n", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
            ]
        },
    )

    assert response

    with open(f"{USER_CERT_PATH}_2", "rb") as user_cert_file2:
        user_cert2 = user_cert_file2.read()
    response = await webadm_api_manager.set_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        {
            "usercertificate": [
                repr(user_cert2.decode())
                .replace("\\n", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
            ]
        },
        True,
    )

    assert response


@pytest.mark.asyncio
async def test_get_config_objects() -> None:
    """
    Test Get_Config_Objects method.
    """
    # Test to get config using wrong type for type_ parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_config_objects("clients")
    assert str(excinfo).startswith(
        f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('type_', 'ConfigObjectType')}')"
    )

    # Test to get config using wrong type for application parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_config_objects(
            ConfigObjectType.CLIENTS, application="openotp"
        )

    assert str(excinfo).startswith(
        f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('application', 'ConfigObjectApplication')}')"
    )

    # Test if getting clients objects with settings parameter not provided returns a list
    response = await webadm_api_manager.get_config_objects(ConfigObjectType.CLIENTS)

    assert isinstance(response, list)

    # Test if getting clients objects with settings parameter set explicitly to qFalse returns a list
    response = await webadm_api_manager.get_config_objects(
        ConfigObjectType.CLIENTS, settings=False
    )

    assert isinstance(response, list)

    # Test if getting clients objects with settings parameter set True returns a dictionary
    response = await webadm_api_manager.get_config_objects(
        ConfigObjectType.CLIENTS, settings=True
    )

    assert isinstance(response, dict)

    # Test if getting clients objects with settings parameter set True, and application set, returns a dictionary
    response = await webadm_api_manager.get_config_objects(
        ConfigObjectType.CLIENTS,
        settings=True,
        application=ConfigObjectApplication.OPENOTP,
    )

    assert isinstance(response, dict)


@pytest.mark.asyncio
async def test_get_event_logs() -> None:
    """
    Test Get_Event_Logs method.
    """
    # Test to get event logs using wrong type for application parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_event_logs("openotp")
    assert str(excinfo).startswith(
        f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('application', 'EventLogApplication')}')"
    )
    # Test to get event logs using max value below 1
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_event_logs(EventLogApplication.OPENOTP, max_=0)

    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('max is not a positive int!')"
    )
    # Test to get event logs for a malformed DN
    response = await webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP, max_=1, dn=RANDOM_STRING
    )

    assert response == []

    # Test to get event logs for a non existing DN
    response = await webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
        max_=1,
        dn=f"CN={RANDOM_STRING},{WEBADM_BASE_DN}",
    )

    assert response == []

    # Test to get event logs for an existing DN without any authentication
    response = await webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
        max_=1,
        dn=f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}",
    )

    assert response == []

    # Test to get only one event log for an existing DN with authentications
    if CLUSTER_TYPE == "mssp":
        user_w_auth = (
            f"CN=u_cp_allowed,{WEBADM_BASE_DN.lower().replace('ou=pyrcdevs,', '')}"
        )
    else:
        user_w_auth = (
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_cp_allowed,"
            f"{WEBADM_BASE_DN.replace('OU=pyrcdevs,', '')}"
        )

    response = await webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
        max_=1,
        dn=user_w_auth,
    )

    assert isinstance(response, list)
    assert len(response) == 1

    # Test to get all event logs for an existing DN with authentications
    response = await webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
        dn=user_w_auth,
    )

    assert isinstance(response, list)
    assert len(response) == 47
    for log in response:
        assert isinstance(log, dict)
        assert all(
            prefix in log
            for prefix in ("client", "dn", "host", "session", "source", "text", "time")
        )
        assert re.compile(REGEX_LOGTIME_TIME).search(log["time"])
        assert log["dn"].lower() == user_w_auth.lower()

    # Test to get all event logs
    response = await webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
    )

    assert isinstance(response, list)
    assert len(response) == 100
    for log in response:
        assert isinstance(log, dict)
        assert all(
            prefix in log
            for prefix in ("client", "dn", "host", "session", "source", "text", "time")
        )
        assert re.compile(REGEX_LOGTIME_TIME).search(log["time"])


@pytest.mark.asyncio
async def test_get_license_details() -> None:
    """
    Test Get_License_Details method.
    """
    # Test to get license details using wrong type for product parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_license_details("openotp")
    assert str(excinfo).startswith(
        f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('product', 'LicenseProduct')}')"
    )

    # Test to get license details for all products
    response = await webadm_api_manager.get_license_details()
    assert isinstance(response, dict)

    assert all(
        key
        in (
            "type",
            "token_pool",
            "cache_time",
            "customer_id",
            "instance_id",
            "valid_from",
            "valid_to",
            "products",
            "error_message",
        )
        for key in response
    )

    assert response["type"] in ["Subscription", "Virtual"]
    if CLUSTER_TYPE != "mssp":
        assert re.compile(r"\d/\d*").search(response["token_pool"])
        assert isinstance(response["cache_time"], int)
        assert re.compile(r"\d*").search(response["instance_id"])
    assert response["customer_id"] is None or re.compile(r"[0-9A-Z]*").search(
        response["customer_id"]
    )

    assert re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").search(
        response["valid_from"]
    )
    assert re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").search(
        response["valid_to"]
    )
    assert response["error_message"] is None

    assert isinstance(response["products"], dict)
    products = response["products"]

    assert all(key in ("OpenOTP", "SpanKey") for key in products)

    assert isinstance(products["OpenOTP"], dict)
    assert all(
        key in ("maximum_users", "allowed_options") for key in products["OpenOTP"]
    )
    assert re.compile(r"\d*").search(str(products["OpenOTP"]["maximum_users"]))
    assert all(
        value in ["AUTH", "SIGN", "VOICE", "BADGE"]
        for value in products["OpenOTP"]["allowed_options"]
    )

    assert isinstance(products["SpanKey"], dict)
    assert all(key in "maximum_hosts" for key in products["SpanKey"])
    assert re.compile(r"\d*").search(products["SpanKey"]["maximum_hosts"])

    # Test to get license details for OpenOTP product
    response = await webadm_api_manager.get_license_details(LicenseProduct.OPENOTP)

    assert isinstance(response, dict)

    assert all(
        key
        in (
            "type",
            "token_pool",
            "cache_time",
            "customer_id",
            "instance_id",
            "valid_from",
            "valid_to",
            "maximum_users",
            "allowed_options",
            "error_message",
        )
        for key in response
    )

    assert response["type"] in ["Subscription", "Virtual"]
    if CLUSTER_TYPE != "mssp":
        assert re.compile(r"\d/\d*").search(response["token_pool"])
        assert isinstance(response["cache_time"], int)
        assert re.compile(r"\d*").search(response["instance_id"])
    assert response["customer_id"] is None or re.compile(r"[0-9A-Z]*").search(
        response["customer_id"]
    )

    assert re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").search(
        response["valid_from"]
    )
    assert re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").search(
        response["valid_to"]
    )
    assert response["error_message"] is None

    assert re.compile(r"\d*").search(str(response["maximum_users"]))
    assert all(
        value in ["AUTH", "SIGN", "VOICE", "BADGE"]
        for value in response["allowed_options"]
    )

    # Test to get license details for SpanKey product
    response = await webadm_api_manager.get_license_details(LicenseProduct.SPANKEY)

    assert isinstance(response, dict)

    assert all(
        key
        in (
            "type",
            "token_pool",
            "cache_time",
            "customer_id",
            "instance_id",
            "valid_from",
            "valid_to",
            "maximum_hosts",
            "error_message",
        )
        for key in response
    )

    assert response["type"] in ["Subscription", "Virtual"]
    if CLUSTER_TYPE != "mssp":
        assert re.compile(r"\d/\d*").search(response["token_pool"])
        assert isinstance(response["cache_time"], int)
        assert re.compile(r"\d*").search(response["instance_id"])
    assert response["customer_id"] is None or re.compile(r"[0-9A-Z]*").search(
        response["customer_id"]
    )

    assert re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").search(
        response["valid_from"]
    )
    assert re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").search(
        response["valid_to"]
    )
    assert response["error_message"] is None

    assert re.compile(r"\d*").search(response["maximum_hosts"])


@pytest.mark.asyncio
async def test_get_random_bytes() -> None:
    """
    Test Get_Random_Bytes method.
    """
    # Test for non positive integer
    with pytest.raises(pyrcdevs.manager.Manager.InvalidParams) as excinfo:
        await webadm_api_manager.get_random_bytes(-1)
    assert str(excinfo).startswith(
        f"<ExceptionInfo InvalidParams('Parameter length not Integer')"
    )

    # Test that different returned random bytes have expected length
    for length in [1, 10, 100, 1000, 10000]:
        response = await webadm_api_manager.get_random_bytes(length)
        assert re.compile(REGEX_BASE64).search(response)
        assert len(base64.b64decode(response)) == length


@pytest.mark.asyncio
async def test_get_user_attrs() -> None:
    """
    Test Get_User_Attrs method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_attrs, 1)

    response = await webadm_api_manager.get_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )

    assert all(
        (
            key in LIST_USER_ACCOUNT_LDAP_SLAPD
            if CLUSTER_TYPE == "mssp"
            else LIST_USER_ACCOUNT_LDAP_AD
        )
        for key in response
    )
    assert response["objectclass"] == DICT_USER_OBJECTCLASS[CLUSTER_TYPE]
    assert all(
        response[key] == [f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1"]
        for key in ["cn", "sn"]
        + (
            ["samaccountname", "name"]
            if CLUSTER_TYPE in ("normal", "metadata")
            else ["uid"]
        )
    )
    assert response["homedirectory"] == [
        f"/home/u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1"
    ]
    assert response["loginshell"] == ["/bin/bash"]
    if CLUSTER_TYPE == "normal":
        assert (
            isinstance(response["webadmdata"], list)
            and len(response["webadmdata"]) == 1
            and isinstance(response["webadmdata"][0], str)
        )
        data = response["webadmdata"][0].split(",")
        assert isinstance(data, list) and len(data) > 0
        assert all(
            re.compile(
                rf".*=({{wcrypt}})*{REGEX_BASE64.replace('$', '').replace('^', '')}"
            ).search(d)
            for d in data
        )
    assert all(
        isinstance(response[key], list)
        and len(response[key]) == 1
        and re.compile(r"\d*(.0Z)*").search(response[key][0])
        for key in (
            [
                "instancetype",
                "usncreated",
                "usnchanged",
                "useraccountcontrol",
                "badpwdcount",
                "codepage",
                "countrycode",
                "lastlogoff",
                "pwdlastset",
                "primarygroupid",
                "accountexpires",
                "logoncount",
                "samaccounttype",
                "lastlogontimestamp",
                "whencreated",
                "whenchanged",
                "dscorepropagationdata",
            ]
            if CLUSTER_TYPE in ("normal", "metadata")
            else [
                "uidnumber",
                "gidnumber",
            ]
        )
    )
    assert (
        isinstance(response["usercertificate"], list)
        and len(response["usercertificate"]) > 0
    )
    assert all(
        re.compile(REGEX_BASE64).search(certificate)
        for certificate in response["usercertificate"]
    )

    # Test for non existing attribute
    response = await webadm_api_manager.get_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        ["nonexistingattribute"],
    )

    assert response == []

    # Test for uidnumber and gidnumber
    response = await webadm_api_manager.get_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        ["uidnumber", "gidnumber"],
    )

    assert response == {
        "gidnumber": [
            "100",
        ],
        "uidnumber": [
            str(uid_numbers[f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1"])
        ],
    }


@pytest.mark.asyncio
async def test_get_user_dn() -> None:
    """
    Test Get_User_DN method.
    """
    # Test with unknown domain
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_dn(RANDOM_STRING, RANDOM_STRING)
    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Domain '{RANDOM_STRING}' not existing\")"
    )

    # Test with unknown user
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_dn(RANDOM_STRING, "Domain_Enabled")
    exception_str = str(excinfo)
    assert exception_str.startswith(
        "<ExceptionInfo InternalError('User not found Domain_Enabled\\\\"
        + rf"{RANDOM_STRING}')"
    )

    # Test existing user
    response = await webadm_api_manager.get_user_dn(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", "Domain_Enabled"
    )

    assert (
        response.lower()
        == f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )


@pytest.mark.asyncio
async def test_get_user_domains() -> None:
    """
    Test Get_User_Domains method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_domains, 1)

    # Test existing user
    response = await webadm_api_manager.get_user_domains(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )

    assert isinstance(response, list)
    assert len(response) > 0


@pytest.mark.asyncio
async def test_get_user_groups() -> None:
    """
    Test Get_User_Groups method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_groups, 1, "Domain_Enabled")

    # Test with unknown domain
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_groups(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
            RANDOM_STRING,
        )

    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"Domain '{RANDOM_STRING}' not existing\")"
    )

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_groups(unknown_user_dn, "Domain_Enabled")

    exception_str = str(excinfo)
    assert exception_str.startswith(
        f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\")"
    )

    response = await webadm_api_manager.get_user_groups(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        "Domain_Enabled",
    )

    assert isinstance(response, list)
    list_groups_lower = [g.lower() for g in response]
    assert list_groups_lower == [
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    ]


@pytest.mark.asyncio
async def test_get_user_data() -> None:
    """
    Test Get_User_Data method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_data, 1)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_data(unknown_user_dn)
    exception_str = str(excinfo)
    assert exception_str.startswith(
        f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\")"
    )

    # Test for all existing data
    response = await webadm_api_manager.get_user_data(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
    )

    assert isinstance(response, dict)
    list_keys = list(response.keys())
    list_keys.sort()
    assert list_keys == [
        "OpenOTP.EmergOTP",
        "OpenOTP.TokenID",
        "OpenOTP.TokenKey",
        "OpenOTP.TokenModel",
        "OpenOTP.TokenSerial",
        "OpenOTP.TokenState",
        "OpenOTP.TokenType",
        "SpanKey.KeyType",
        "SpanKey.PublicKey",
    ]

    # Test for non existing data
    response = await webadm_api_manager.get_user_data(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        [f"{RANDOM_STRING}.{RANDOM_STRING}"],
    )

    assert response == []

    # Test for 2 existing data
    response = await webadm_api_manager.get_user_data(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        [
            "OpenOTP.EmergOTP",
            "OpenOTP.TokenID",
        ],
    )

    assert isinstance(response, dict)
    list_keys = list(response.keys())
    list_keys.sort()
    assert list_keys == [
        "OpenOTP.EmergOTP",
        "OpenOTP.TokenID",
    ]


@pytest.mark.asyncio
async def test_get_user_certificates() -> None:
    """
    Test Get_User_Certificates method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_certificates, 1)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_certificates(unknown_user_dn)
    exception_str = str(excinfo)
    assert exception_str.startswith(
        f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\")"
    )

    # Test existing user without certificates
    response = await webadm_api_manager.get_user_certificates(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower()
    )

    assert response == []

    # Test existing user with certificates
    with open(USER_CERT_PATH, "r") as f:
        cert = "".join(f.readlines()).replace(
            "-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----"
        )
    with open(f"{USER_CERT_PATH}_2", "r") as f2:
        cert2 = "".join(f2.readlines()).replace(
            "-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----"
        )
    response = await webadm_api_manager.get_user_certificates(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )

    response.sort()
    expected_certs = [cert2, cert]
    expected_certs.sort()
    assert response == expected_certs


@pytest.mark.asyncio
async def test_get_user_settings() -> None:
    """
    Test Get_User_Settings method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_settings, 1)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_settings(unknown_user_dn)
    exception_str = str(excinfo)
    assert exception_str.startswith(
        f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\")"
    )

    # Test for all existing settings
    response = await webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
    )

    assert isinstance(response, dict)
    assert response.keys() >= {
        "HelpDesk.AllowOTPTypes",
        "HelpDesk.AllowOpenOTP",
        "HelpDesk.AllowPKI",
        "HelpDesk.AllowPassword",
        "HelpDesk.AllowRegister",
        "HelpDesk.AllowSSHKeyTypes",
        "HelpDesk.AllowSpanKey",
        "HelpDesk.AllowTokenTypes",
        "HelpDesk.AllowUnlock",
        "HelpDesk.AllowUserActivation",
        "HelpDesk.AllowUserInfos",
        "HelpDesk.DefaultTokenType",
        "HelpDesk.EmergencyExpire",
        "HelpDesk.EmergencyMaxUse",
        "HelpDesk.MaxTokens",
        "HelpDesk.SendPin",
        "HelpDesk.SendPinMessage",
        "HelpDesk.UserSearchAttrs",
        "HelpDesk.UserSearchScopes",
        "OpenID.AWSRoleNames",
        "OpenID.AWSSessionTime",
        "OpenID.ApplicationSSO",
        "OpenID.AutoConfirm",
        "OpenID.SessionTimeout",
        "OpenOTP.BadgingArea",
        "OpenOTP.BadgingData",
        "OpenOTP.BadgingLocations",
        "OpenOTP.BadgingMode",
        "OpenOTP.BlockNotify",
        "OpenOTP.BlockTime",
        "OpenOTP.ChallengeTimeout",
        "OpenOTP.EnableConfirm",
        "OpenOTP.EnableLogin",
        "OpenOTP.ExpireNotify",
        "OpenOTP.HOTPLookAheadWindow",
        "OpenOTP.LastOTPPerIP",
        "OpenOTP.LastOTPTime",
        "OpenOTP.ListAlgorithm",
        "OpenOTP.ListChallengeMode",
        "OpenOTP.ListSize",
        "OpenOTP.LockTimer",
        "OpenOTP.LoginMode",
        "OpenOTP.MailMode",
        "OpenOTP.MaxIdle",
        "OpenOTP.MaxTries",
        "OpenOTP.MaxWeak",
        "OpenOTP.MobileTimeout",
        "OpenOTP.OCRASuite",
        "OpenOTP.OTPFallback",
        "OpenOTP.OTPLength",
        "OpenOTP.OTPPrefix",
        "OpenOTP.OTPType",
        "OpenOTP.OfflineExpire",
        "OpenOTP.PasswordCheck",
        "OpenOTP.PasswordReset",
        "OpenOTP.PrefetchExpire",
        "OpenOTP.PushCommit",
        "OpenOTP.PushLogin",
        "OpenOTP.PushVoice",
        "OpenOTP.RecordEvents",
        "OpenOTP.ReplyData",
        "OpenOTP.SMSMode",
        "OpenOTP.SMSType",
        "OpenOTP.SecureMail",
        "OpenOTP.SelfRegister",
        "OpenOTP.TOTPTimeOffsetWindow",
        "OpenOTP.TOTPTimeStep",
        "OpenOTP.TokenExpire",
        "OpenOTP.U2FPINMode",
        "OpenOTP.ValidFrom",
        "OpenOTP.ValidTo",
        "OpenOTP.WeakNotify",
        "PwReset.AllowUnlock",
        "PwReset.LinkMode",
        "PwReset.LinkTime",
        "PwReset.PasswordAlpha",
        "PwReset.PasswordByLength",
        "PwReset.PasswordCase",
        "PwReset.PasswordMaxLength",
        "PwReset.PasswordMinLength",
        "PwReset.PasswordNumeric",
        "PwReset.PasswordStrength",
        "PwReset.PasswordSymbol",
        "PwReset.SMSType",
        "PwReset.SecureMail",
        "SelfDesk.AllowBadging",
        "SelfDesk.AllowOTPTypes",
        "SelfDesk.AllowOpenOTP",
        "SelfDesk.AllowPKI",
        "SelfDesk.AllowPassword",
        "SelfDesk.AllowRegister",
        "SelfDesk.AllowSSHKeyTypes",
        "SelfDesk.AllowSign",
        "SelfDesk.AllowSpanKey",
        "SelfDesk.AllowTokenTypes",
        "SelfDesk.AllowUserInfos",
        "SelfDesk.CertValidity",
        "SelfDesk.DefaultTokenType",
        "SelfDesk.EmergencyExpire",
        "SelfDesk.EmergencyMaxUse",
        "SelfDesk.KeyPasswordLength",
        "SelfReg.AllowRegister",
        "SelfReg.AllowSSHKeyTypes",
        "SelfReg.AllowTokenTypes",
        "SelfReg.CertValidity",
        "SelfReg.DefaultTokenType",
        "SelfReg.KeyPasswordLength",
        "SelfReg.LinkMode",
        "SelfReg.LinkTime",
        "SelfReg.SMSType",
        "SelfReg.SecureMail",
        "SpanKey.AddressFilter",
        "SpanKey.AgentForwarding",
        "SpanKey.AllowKeyFiles",
        "SpanKey.AllowUserCerts",
        "SpanKey.AllowedGroup",
        "SpanKey.AllowedTags",
        "SpanKey.EnableLogin",
        "SpanKey.EnvVariables",
        "SpanKey.ExpireNotify",
        "SpanKey.ForwardFilter",
        "SpanKey.GuestAccount",
        "SpanKey.KeyExpire",
        "SpanKey.KeyMaxUse",
        "SpanKey.LockSessionTime",
        "SpanKey.MaxSessionTime",
        "SpanKey.OTPType",
        "SpanKey.OTPTypeNI",
        "SpanKey.PTYAllocation",
        "SpanKey.PasswordChange",
        "SpanKey.PasswordReset",
        "SpanKey.PortForwarding",
        "SpanKey.RecordAuditLogs",
        "SpanKey.RecordSessions",
        "SpanKey.RemoteCommand",
        "SpanKey.RequireMFA",
        "SpanKey.SelfRegister",
        "SpanKey.SessionBadgeOut",
        "SpanKey.SudoCommands",
        "SpanKey.ValidFrom",
        "SpanKey.ValidTo",
        "SpanKey.X11Forwarding",
    }

    # Test for non existing data
    response = await webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        [f"{RANDOM_STRING}.{RANDOM_STRING}"],
    )

    assert response == []

    # Test for 2 existing data
    response = await webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        [
            "SpanKey.PortForwarding",
            "OpenOTP.ValidFrom",
        ],
    )

    assert isinstance(response, dict)
    list_keys = list(response.keys())
    list_keys.sort()
    assert list_keys == [
        "OpenOTP.ValidFrom",
        "SpanKey.PortForwarding",
    ]


@pytest.mark.asyncio
async def test_get_user_ids() -> None:
    """
    Test Get_User_IDs method.
    """
    # Test issue with DN parameter
    await _test_malformed_dns(webadm_api_manager.get_user_ids, 1)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.get_user_ids(unknown_user_dn)
    exception_str = str(excinfo)
    assert exception_str.startswith(
        f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\")"
    )

    # Test existing user
    response = await webadm_api_manager.get_user_ids(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )

    assert isinstance(response, list)
    assert response == [f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1"]


@pytest.mark.asyncio
async def test_get_qrcode() -> None:
    """
    Test Get_QRCode method.
    """
    # Test with bad type for size argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_qrcode("https://www.rcdevs.com", size=1)
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('size type is not QRCodeSize')"
    )

    # Test with bad type for format argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_qrcode("https://www.rcdevs.com", format_="PNG")
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('format type is not QRCodeFormat')"
    )

    # Test with bad type for margin argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.get_qrcode("https://www.rcdevs.com", margin=1)
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('margin type is not QRCodeMargin')"
    )

    # Test that only providing url returns a GIF
    response = await webadm_api_manager.get_qrcode("https://www.rcdevs.com")
    assert re.compile(REGEX_BASE64).search(response)
    image_data = base64.b64decode(response)
    image = Image.open(BytesIO(image_data))
    assert image.format == "GIF"

    # Test providing image format returns corresponding format
    for image_format in QRCodeFormat:
        response = await webadm_api_manager.get_qrcode(
            "https://www.rcdevs.com", format_=image_format
        )

        assert re.compile(REGEX_BASE64).search(response)
        image_data = base64.b64decode(response)
        if image_format == QRCodeFormat.TXT:
            try:
                image_data.decode("utf-8")
            except (LookupError, UnicodeDecodeError):
                assert "TXT image is not UTF-8" == ""
            continue
        image = Image.open(BytesIO(image_data))
        assert (
            image.format == "JPEG"
            if image_format == QRCodeFormat.JPG
            else image_format.value
        )

    for image_format in QRCodeFormat:
        if image_format == QRCodeFormat.TXT:
            continue
        for image_size in QRCodeSize:
            for image_margin in QRCodeMargin:
                response = await webadm_api_manager.get_qrcode(
                    "https://www.rcdevs.com",
                    size=image_size,
                    format_=image_format,
                    margin=image_margin,
                )

                assert re.compile(REGEX_BASE64).search(response)
                image_data = base64.b64decode(response)
                image = Image.open(BytesIO(image_data))
                assert image.size == (
                    (25 + image_margin.value * 2) * image_size.value,
                    (25 + image_margin.value * 2) * image_size.value,
                )


@pytest.mark.asyncio
async def test_import_inventory_item() -> None:
    """
    Test Import_Inventory_Item method.
    """

    # Test with bad type for  argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.import_inventory_item(
            "OTP Token",
            "151147490827268",
            "Yubikey #2573124",
            {
                "TokenType": "WVVCSUtFWQ==",
                "TokenID": "iXfEf9wE",
                "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
                "DataMode": "Aw==",
                "TokenState": "NzY4",
            },
            status="Valid",
        )
        # NOSONAR
    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("status", "InventoryStatus")
    )

    # Test importing Yubikey
    response = await webadm_api_manager.import_inventory_item(
        "OTP Token",
        "151147490827268",
        "Yubikey #2573124",
        {
            "TokenType": "WVVCSUtFWQ==",
            "TokenID": "iXfEf9wE",
            "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
            "DataMode": "Aw==",
            "TokenState": "NzY4",
        },
    )

    assert response

    # Test importing same Yubikey a second time
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.import_inventory_item(
            "OTP Token",
            "151147490827268",
            "Yubikey #2573124",
            {
                "TokenType": "WVVCSUtFWQ==",
                "TokenID": "iXfEf9wE",
                "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
                "DataMode": "Aw==",
                "TokenState": "NzY4",
            },
        )

    assert (
        "Duplicate entry 'OTP Token-151147490827268' for key 'Inventory.PRIMARY'\")"
        in str(excinfo)
        or "Duplicate entry 'OTP Token-151147490827268' for key 'PRIMARY'\")"
        in str(excinfo)
        or 'SQL query error: ERROR: duplicate key value violates unique constraint "Inventory_pkey'
        in str(excinfo)
        or 'SQL query error: [FreeTDS][SQL Server]Violation of PRIMARY KEY constraint'
        in str(excinfo)
    )

    # Test importing a yubikey with status to expired
    response = await webadm_api_manager.import_inventory_item(
        "OTP Token",
        "100000000000000001",
        "Yubikey #2573124",
        {
            "TokenType": "WVVCSUtFWQ==",
            "TokenID": "iXfEf9wE",
            "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
            "DataMode": "Aw==",
            "TokenState": "NzY4",
        },
        status=InventoryStatus.EXPIRED,
    )

    assert response

    # Test importing a yubikey with status to lost
    response = await webadm_api_manager.import_inventory_item(
        "OTP Token",
        "100000000000000002",
        "Yubikey #2573124",
        {
            "TokenType": "WVVCSUtFWQ==",
            "TokenID": "iXfEf9wE",
            "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
            "DataMode": "Aw==",
            "TokenState": "NzY4",
        },
        status=InventoryStatus.LOST,
    )

    assert response

    # Test importing a yubikey with status to valid
    response = await webadm_api_manager.import_inventory_item(
        "OTP Token",
        "100000000000000003",
        "Yubikey #2573124",
        {
            "TokenType": "WVVCSUtFWQ==",
            "TokenID": "iXfEf9wE",
            "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
            "DataMode": "Aw==",
            "TokenState": "NzY4",
        },
        status=InventoryStatus.VALID,
    )

    assert response

    # Test importing a yubikey with status to broken
    response = await webadm_api_manager.import_inventory_item(
        "OTP Token",
        "100000000000000004",
        "Yubikey #2573124",
        {
            "TokenType": "WVVCSUtFWQ==",
            "TokenID": "iXfEf9wE",
            "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
            "DataMode": "Aw==",
            "TokenState": "NzY4",
        },
        status=InventoryStatus.BROKEN,
    )

    assert response

    # Test importing a yubikey with status to broken
    response = await webadm_api_manager.import_inventory_item(
        "OTP Token",
        "100000000000000005",
        "Yubikey #2573124",
        {
            "TokenType": "WVVCSUtFWQ==",
            "TokenID": "iXfEf9wE",
            "TokenKey": "SddJ2mYccUe1y9TbPxUte+jH0PT/tQ==",
            "DataMode": "Aw==",
            "TokenState": "NzY4",
        },
        active=False,
    )

    assert response

    # Test importing PIV
    response = await webadm_api_manager.import_inventory_item(
        "PIV Device",
        "67090940",
        "PIV NitroKey",
        {
            "PublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwiBZ8g4yHliKPSr"
            "/Kg4EcAJLHch+Kh6w6emzn9ZRxSfrBofSO45x17oi7UsG8OIrBRMIVTgXOzqMbT"
            "wnnPjkpep9dKe4FHEMaPEvNYhAwHDMGVhbYBcf7Ru3CsCM9NPqmbjeV/+zGsMxq8X"
            "bZLKPdoW4EjtneTpqD8ummip1ZBTuaFXGi3D/SDxAWTy3DlA+QtU5E2HpU7tZghi5"
            "ygiy9przQct/pMCNX8WJgkLC58g/UtnVeClkh2GGalFrODR2hY0lhWQYhzNH5FzIBm"
            "EENcPucSwB7/r0abV9hdW52qWXECGBIjKAXrA16n/4QsFJNlPJaysl5Pv4ZBqM86jo"
            "gwIDAQAB"
        },
    )

    assert response


@pytest.mark.asyncio
async def test_link_inventory_item() -> None:
    """
    Test Link_Inventory_Item method.
    """

    await _test_malformed_dns(
        webadm_api_manager.link_inventory_item, 3, "OTP Token", "100000000000001"
    )

    response = await webadm_api_manager.link_inventory_item(
        "OTP Token",
        "100000000000000001",
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
    )

    assert response


@pytest.mark.asyncio
async def test_search_inventory_items() -> None:
    """
    Test Search_Inventory_Items method.
    """
    # sleep for 5 seconds to avoid having same current time as import time
    time.sleep(5)

    # Get current time
    current_time = datetime.now()
    one_hour_earlier = current_time - timedelta(hours=1)
    current_time_formatted = current_time.strftime("%Y-%m-%d %H:%M:%S")
    one_hour_earlier_formatted = one_hour_earlier.strftime("%Y-%m-%d %H:%M:%S")

    # Test with bad type for status argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.search_inventory_items("OTP Token", status="Valid")
        # NOSONAR
    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("status", "InventoryStatus")
    )

    # Get all OTP Token items
    response = await webadm_api_manager.search_inventory_items("OTP Token")
    response.sort()
    assert response == [
        "100000000000000001",
        "100000000000000002",
        "100000000000000003",
        "100000000000000004",
        "100000000000000005",
        "151147490827268",
    ]

    # Get all PIV items
    response = await webadm_api_manager.search_inventory_items("PIV Device")
    assert response == [
        "67090940",
    ]

    # Get all enabled OTP Token items
    response = await webadm_api_manager.search_inventory_items("OTP Token", active=True)

    response.sort()
    assert response == [
        "100000000000000001",
        "100000000000000002",
        "100000000000000003",
        "100000000000000004",
        "151147490827268",
    ]

    # Get all disabled OTP Token items
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", active=False
    )

    assert response == [
        "100000000000000005",
    ]

    # Get all valid OTP Token items
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", status=InventoryStatus.VALID
    )

    response.sort()
    assert response == [
        "100000000000000003",
        "100000000000000005",
        "151147490827268",
    ]

    # Get all expired OTP Token items
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", status=InventoryStatus.EXPIRED
    )

    assert response == [
        "100000000000000001",
    ]

    # Get all lost OTP Token items
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", status=InventoryStatus.LOST
    )

    assert response == [
        "100000000000000002",
    ]

    # Get all broken OTP Token items
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", status=InventoryStatus.BROKEN
    )

    assert response == [
        "100000000000000004",
    ]

    # Get all OTP Token with two consecutive 00 in reference
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", filter_="*00*"
    )

    response.sort()
    assert response == [
        "100000000000000001",
        "100000000000000002",
        "100000000000000003",
        "100000000000000004",
        "100000000000000005",
    ]

    # Get all linked OTP Token
    response = await webadm_api_manager.search_inventory_items("OTP Token", linked=True)

    assert response == [
        "100000000000000001",
    ]

    # Get all unlinked OTP Token
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", linked=False
    )

    response.sort()
    assert response == [
        "100000000000000002",
        "100000000000000003",
        "100000000000000004",
        "100000000000000005",
        "151147490827268",
    ]

    # Test for items imported after current time (must be zero items)
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", start=current_time_formatted
    )

    assert response == []

    # Test for items imported at least one hour ago (must be all OTP Token items)
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", start=one_hour_earlier_formatted
    )

    response.sort()
    assert response == [
        "100000000000000001",
        "100000000000000002",
        "100000000000000003",
        "100000000000000004",
        "100000000000000005",
        "151147490827268",
    ]

    # Test for items imported at most one hour ago (must be zero items)
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", stop=one_hour_earlier_formatted
    )

    assert response == []

    # Test for items imported before current time (must be all OTP Token items)
    response = await webadm_api_manager.search_inventory_items(
        "OTP Token", stop=current_time_formatted
    )

    response.sort()
    assert response == [
        "100000000000000001",
        "100000000000000002",
        "100000000000000003",
        "100000000000000004",
        "100000000000000005",
        "151147490827268",
    ]


@pytest.mark.asyncio
async def test_check_user_badging() -> None:
    """
    Test Check_User_Badging method.
    """

    current_timestamp = datetime.timestamp(datetime.now())
    time.sleep(5)

    # Test with non existing object
    response = await webadm_api_manager.check_user_badging(RANDOM_STRING)
    assert not response

    # Test with existing object but not badged in
    user_dn = f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}"
    if CLUSTER_TYPE == "mssp":
        user_dn = user_dn.lower()
    response = await webadm_api_manager.check_user_badging(user_dn)
    assert not response

    webbadge(
        WEBADM_HOST,
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4",
        DEFAULT_PASSWORD,
        "Domain_Enabled",
        BadgingAction.IN,
    )

    # Test with existing badged in object
    response = await webadm_api_manager.check_user_badging(user_dn)
    assert isinstance(response, int)
    assert response - current_timestamp >= 4


@pytest.mark.asyncio
async def test_move_ldap_object() -> None:
    """
    Test Move_LDAP_Object method.
    """

    await _test_malformed_dns(
        webadm_api_manager.move_ldap_object, 1, f"ou=new_ou,{WEBADM_BASE_DN}"
    )

    response = await webadm_api_manager.move_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5,{WEBADM_BASE_DN}",
        f"ou=new_ou,{WEBADM_BASE_DN}",
    )

    assert response


@pytest.mark.asyncio
async def test_rename_ldap_object() -> None:
    """
    Test Rename_LDAP_Object method.
    """

    await _test_malformed_dns(webadm_api_manager.rename_ldap_object, 1, "new_name")

    response = await webadm_api_manager.rename_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5,ou=new_ou,{WEBADM_BASE_DN}",
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n",
    )

    assert response


@pytest.mark.asyncio
async def test_remove_user_attrs() -> None:
    """
    Test Remove_User_Attrs method.
    """

    await _test_malformed_dns(
        webadm_api_manager.remove_user_attrs, 1, {"mobile": ["+33123456789"]}
    )

    # Determine attribute which can have multiple values
    tested_attribute = "description" if CLUSTER_TYPE == "mssp" else "proxyaddresses"

    # Add two values for proxyAddresses attribute
    response = await webadm_api_manager.set_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        {tested_attribute: ["value1", "value2"]},
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        attrs=[tested_attribute],
    )

    assert isinstance(response, dict)
    keys = list(response.keys())
    assert len(keys) == 1
    assert (
        keys[0].lower()
        == f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,OU=new_ou,{WEBADM_BASE_DN}".lower()
    )
    values = list(response.values())
    assert len(values) == 1
    assert values[0] == {tested_attribute: ["value1", "value2"]} or values[0] == {
        tested_attribute: ["value2", "value1"]
    }

    response = await webadm_api_manager.remove_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        {tested_attribute: ["value1"]},
        True,
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        attrs=[tested_attribute],
    )

    assert isinstance(response, dict)
    keys = list(response.keys())
    assert len(keys) == 1
    assert (
        keys[0].lower()
        == f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,OU=new_ou,{WEBADM_BASE_DN}".lower()
    )
    values = list(response.values())
    assert len(values) == 1
    assert values[0] == {tested_attribute: ["value2"]}

    response = await webadm_api_manager.remove_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        [tested_attribute],
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        attrs=[tested_attribute],
    )

    assert isinstance(response, dict)
    keys = list(response.keys())
    assert len(keys) == 1
    assert (
        keys[0].lower()
        == f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,OU=new_ou,{WEBADM_BASE_DN}".lower()
    )
    values = list(response.values())
    assert len(values) == 1
    assert values[0] == []


@pytest.mark.asyncio
async def test_remove_ldap_object() -> None:
    """
    Test Remove_LDAP_Object method.
    """

    await _test_malformed_dns(webadm_api_manager.remove_ldap_object, 1)

    response = await webadm_api_manager.remove_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
    )

    assert response

    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.search_ldap_objects(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,ou=new_ou,{WEBADM_BASE_DN}",
        )

    assert str(excinfo).startswith(
        f"<ExceptionInfo InternalError(\"LDAP container 'CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_5_n,"
        f"ou=new_ou,{WEBADM_BASE_DN}' does not exist\")"
    )


@pytest.mark.asyncio
async def test_remove_user_certificate() -> None:
    """
    Test Remove_User_Certificate method.
    """

    with open(f"{USER_CERT_PATH}", "r") as f:
        cert1 = "".join(f.readlines()).replace(
            "-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----"
        )

    with open(f"{USER_CERT_PATH}_2", "r") as f:
        cert2 = "".join(f.readlines()).replace(
            "-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----"
        )

    with open(f"{USER_CERT_PATH}_3", "r") as f:
        cert3 = "".join(f.readlines()).replace(
            "-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----"
        )

    await _test_malformed_dns(webadm_api_manager.remove_user_certificate, 1, cert3)

    # Test removing an unknown certificate
    response = await webadm_api_manager.remove_user_certificate(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}", cert3
    )

    assert not response

    # Get current certificate of user
    response = await webadm_api_manager.get_user_certificates(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )

    response.sort()
    expected_certs = [cert1, cert2]
    expected_certs.sort()
    assert response == expected_certs

    # Test removing certificate #2
    response = await webadm_api_manager.remove_user_certificate(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}", cert2
    )

    assert response

    # Get current certificate of user
    response = await webadm_api_manager.get_user_certificates(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )

    assert response == [cert1]


@pytest.mark.asyncio
async def test_search_ldap_objects() -> None:
    """
    Test Search_LDAP_Objects method.
    """

    # Test get all object in root of pyrcdevs tests (without scope provided)
    response = await webadm_api_manager.search_ldap_objects(f"{WEBADM_BASE_DN}")
    assert isinstance(response, dict)
    list_keys = [k.lower() for k in response.keys()]
    assert list_keys == [
        WEBADM_BASE_DN.lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}".lower(),
        f"cn=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        f"cn=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower(),
        f"ou=new_ou,{WEBADM_BASE_DN}".lower(),
    ]

    # Test with wrong scope type.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.search_ldap_objects(f"{WEBADM_BASE_DN}", scope="BASE")

    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('scope type is not LDAPSearchScope')"
    )

    # Test get all object in root of pyrcdevs tests (with scope provided)
    response = await webadm_api_manager.search_ldap_objects(
        f"{WEBADM_BASE_DN}", scope=LDAPSearchScope.SUB
    )

    assert isinstance(response, dict)
    list_keys = [k.lower() for k in response.keys()]
    assert list_keys == [
        WEBADM_BASE_DN.lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}".lower(),
        f"cn=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        f"cn=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower(),
        f"ou=new_ou,{WEBADM_BASE_DN}".lower(),
    ]

    # Test get only base
    response = await webadm_api_manager.search_ldap_objects(
        f"{WEBADM_BASE_DN}", scope=LDAPSearchScope.BASE
    )

    assert isinstance(response, dict)
    list_keys = [k.lower() for k in response.keys()]
    assert list_keys == [
        WEBADM_BASE_DN.lower(),
    ]

    # Test get only base
    response = await webadm_api_manager.search_ldap_objects(
        f"{WEBADM_BASE_DN}", scope=LDAPSearchScope.ONE
    )

    assert isinstance(response, dict)
    list_keys = [k.lower() for k in response.keys()]
    list_keys.sort()
    assert list_keys == [
        f"cn=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        f"cn=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}".lower(),
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}".lower(),
        f"ou=new_ou,{WEBADM_BASE_DN}".lower(),
    ]

    if CLUSTER_TYPE != "metadata":
        # Test get only webadmaccount object
        response = await webadm_api_manager.search_ldap_objects(
            f"{WEBADM_BASE_DN}",
            scope=LDAPSearchScope.ONE,
            filter_="(objectclass=webadmaccount)",
        )

        assert isinstance(response, dict)
        list_keys = [k.lower() for k in response.keys()]
        list_keys.sort()
        assert list_keys == [
            f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
            f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}".lower(),
        ]


def check_email_is_received(from_, to, message, is_encrypted=False):
    time.sleep(1)
    email_messages = get_mailbox_content(to)
    assert isinstance(email_messages, list)
    assert len(email_messages) > 0
    last_email = email_messages[-1]
    assert isinstance(last_email, dict)

    assert all(
        prefix in last_email for prefix in ("Date", "From", "To", "body", "subject")
    )
    assert last_email["From"] == from_
    assert last_email["To"] == to
    assert last_email["subject"] == message
    assert isinstance(last_email["body"], list)
    if is_encrypted:
        out = decrypt_smime_message(last_email)
        assert out.startswith(b"Content-Type: multipart/mixed;")
        body_parts = get_body_from_dec_msg(out)
    else:
        body_parts = last_email["body"]

    plain_text_body = " ".join(
        [
            str(a["content_attachment"])
            for a in body_parts
            if "text/plain" in a["content_type"]
        ]
    )
    assert message in plain_text_body
    if " 3" in message or " 4" in message:
        pdf = [
            a["content_attachment"]
            for a in body_parts
            if "application/octet-stream" in a["content_type"]
        ]
        expected_sha512_hex = get_file_sha_hash("tests/test_file.pdf")
        assert len(pdf) == 1
        assert isinstance(pdf[0], bytes)
        received_sha512_hex = get_file_sha_hash(pdf[0])
        assert expected_sha512_hex == received_sha512_hex


def get_body_from_dec_msg(out):
    boundaries = re.compile(r" boundary=\"([^\"]*)\"").findall(out.decode())
    assert len(boundaries) == 1
    boundary = boundaries[0]
    attachments = out.decode().split(f"--{boundary}")
    body_parts = []
    for attach in attachments:
        if "Content-Type:" in attach and "Content-Type: multipart/mixed;" not in attach:
            details = attach.split("\r\n\r\n")
            if "application/octet-stream" in details[0]:
                content = base64.b64decode(details[1])
            else:
                content = details[1]
            body_parts.append(
                {
                    "content_disposition": None,
                    "content_type": details[0].replace("\r\n", ""),
                    "content_attachment": content,
                }
            )
    return body_parts


def decrypt_smime_message(last_email):
    smime = SMIME.SMIME()
    smime.load_key("/tmp/user.key", "/tmp/user.crt")
    assert len(last_email["body"]) == 1
    attachment: str = last_email["body"][0]["content_attachment"]
    attachment = attachment.replace(
        'MIME-Version: 1.0\r\nContent-Disposition: attachment; filename="smime.p7m"\r\nContent-Type: '
        'application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\r\n'
        "Content-Transfer-Encoding: base64\r\n",
        "-----BEGIN PKCS7-----",
    )
    attachment = attachment + "-----END PKCS7-----\r\n"
    attachment = attachment.replace("\r\n\r\n", "")
    p7_bio = BIO.MemoryBuffer(attachment.encode())
    p7 = SMIME.load_pkcs7_bio(p7_bio)
    out = smime.decrypt(p7)
    return out


def get_file_sha_hash(file: str | bytes, method=hashlib.sha512):
    sha_hash_method = method()
    if isinstance(file, str):
        with open(file, "rb") as pdf_file:
            for chunk in iter(lambda: pdf_file.read(4096), b""):
                sha_hash_method.update(chunk)
    else:
        sha_hash_method.update(file)
    return sha_hash_method.hexdigest()


@pytest.mark.asyncio
async def test_send_mail() -> None:
    """
    Test Send_Mail method.
    """

    # For mssp, check this is not possible to send mail
    if CLUSTER_TYPE == "mssp":
        with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
            await webadm_api_manager.send_mail(
                f"cp_allowed-{CLUSTER_TYPE.lower()}@testing.local", "Test", "Test"
            )

        assert str(excinfo).startswith(
            "<ExceptionInfo InternalError('Send email not allowed for tenants')"
        )
    else:
        from_1 = f"noreply-{CLUSTER_TYPE.lower()}@testing.local"
        from_2 = f"noreply-{CLUSTER_TYPE.lower()}_2@testing.local"
        to = f"cp_allowed-{CLUSTER_TYPE.lower()}@testing.local"
        message = f"test_send_mail({RANDOM_STRING}) {{}}"

        # Test sending message using providing to, subject and body
        response = await webadm_api_manager.send_mail(
            to, message.format(1), message.format(1)
        )

        assert response
        check_email_is_received(from_1, to, message.format(1))

        # Test sending message using providing from_, to, subject and body
        response = await webadm_api_manager.send_mail(
            to,
            message.format(2),
            message.format(2),
            from_=from_2,
        )

        assert response
        check_email_is_received(from_2, to, message.format(2))

        with open("tests/test_file.pdf", "rb") as test_file:
            test_pdf = base64.b64encode(test_file.read())
        attachments = [{"name": "test_file.pdf", "data": test_pdf.decode("utf-8")}]

        response = await webadm_api_manager.send_mail(
            to,
            message.format(3),
            message.format(3),
            from_=from_2,
            attachments=attachments,
        )

        assert response
        check_email_is_received(from_2, to, message.format(3))

        with open(f"{USER_CERT_PATH}", "r") as f:
            cert1 = "".join(f.readlines()).replace(
                "-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----"
            )

        response = await webadm_api_manager.send_mail(
            to,
            message.format(4),
            message.format(4),
            from_=from_2,
            attachments=attachments,
            certificate=cert1,
        )

        assert response
        check_email_is_received(from_2, to, message.format(4), True)


@pytest.mark.asyncio
async def test_send_push() -> None:
    """
    Test Send_Push method.
    """

    push_id = base64.b64decode(OPENOTP_PUSHID).decode("utf-8")

    # Test with wrong push ID format
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.send_push(RANDOM_STRING, OPENOTP_PUSHID)
    assert str(excinfo).startswith(
        '<ExceptionInfo InternalError("Invalid device for push notification (bad format '
        f"'{OPENOTP_PUSHID[:25]}...')\")"
    )

    # Test with unknown application ID
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.send_push(RANDOM_STRING, push_id)
    assert str(excinfo).startswith(
        "<ExceptionInfo InternalError('Push message request failed (from service: internal error while calling "
        "PUSH:SEND_SINGLE_PUSH)')"
    )

    # Test right application ID and push ID, but without options and data
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        await webadm_api_manager.send_push("token", push_id)
    assert str(excinfo).startswith(
        "<ExceptionInfo InternalError('Push message request failed (from service: internal error while calling "
        "PUSH:SEND_SINGLE_PUSH)')"
    )

    # Test right application ID and push ID, with options and data
    response = await webadm_api_manager.send_push(
        "token",
        push_id,
        options={
            "title": "Test",
            "body": f"Received from OpenOTP at {CLUSTER_TYPE.upper()}",
            "vibrate": 1,
            "category": "auth",
        },
        data={
            "version": 3,
            "session": "GN8edu7CD0LAayVx",
            "category": "auth",
            "language": "DE",
            "challenge": "b1f2bbf715f20290dacb30f0990eec45aed5d9b0",
            "timestamp": "67d3f640",
            "signature": "c0c1d4c6c0ab743923731464553afa8c41360fc3",
            "client": "560537702ebb33204ed726860c0d5efe",
            "timeout": 90,
            "pinlength": 0,
            "reqtime": 28,
            "source": "175b2c756f8736934f8e153ab23d0212",
            "location": "",
            "endpoint": "3299ec2db609bb9c95f3f0d8f87053a5e5605a628dcafe2d"
            "a2839bf833741a96da482202134a299e15bd2a80b1935b15",
            "config": "374fd86e",
        },
    )

    assert response

    # TODO: a bug with timeout must be checked
    """
    # Test right application ID and push ID, with options and data, and a timeout
    response = await webadm_api_manager.send_push(
        "token",
        push_id,
        options={
            "title": "Test",
            "body": f"Received from OpenOTP at {CLUSTER_TYPE.upper()}",
            "vibrate": 1,
            "category": "auth",
        },
        data={
            "version": 3,
            "session": "GN8edu7CD0LAayVx",
            "category": "auth",
            "language": "DE",
            "challenge": "b1f2bbf715f20290dacb30f0990eec45aed5d9b0",
            "timestamp": "67d3f640",
            "signature": "c0c1d4c6c0ab743923731464553afa8c41360fc3",
            "client": "560537702ebb33204ed726860c0d5efe",
            "timeout": 90,
            "pinlength": 0,
            "reqtime": 28,
            "source": "175b2c756f8736934f8e153ab23d0212",
            "location": "",
            "endpoint": "3299ec2db609bb9c95f3f0d8f87053a5e5605a628dcafe2
            da2839bf833741a96da482202134a299e15bd2a80b1935b15",
            "config": "374fd86e",
        },
        timeout="90",
    )
    assert response"""


@pytest.mark.asyncio
async def test_set_user_password() -> None:
    """
    Test Set_User_Password method.
    """

    await _test_malformed_dns(webadm_api_manager.set_user_password, 1, "Password123!")

    response = await webadm_api_manager.set_user_password(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        "Password321!",
    )

    assert response

    response = await webadm_api_manager.set_user_password(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        DEFAULT_PASSWORD,
        False,
    )

    assert response


@pytest.mark.asyncio
async def test_set_user_settings() -> None:
    """
    Test Set_User_Settings method.
    """

    # Test setting OpenOTP.LoginMode to LDAP
    response = await webadm_api_manager.set_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        {"OpenOTP.LoginMode": "LDAP"},
    )

    assert response

    response = await webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        ["OpenOTP.LoginMode"],
    )

    assert response == {
        "OpenOTP.LoginMode": "LDAP",
    }

    # Test setting OpenOTP.LoginMode back to LDAPOTP
    response = await webadm_api_manager.set_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        {"OpenOTP.LoginMode": "LDAPOTP"},
    )

    assert response

    response = await webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        ["OpenOTP.LoginMode"],
    )

    assert response == {
        "OpenOTP.LoginMode": "LDAPOTP",
    }


@pytest.mark.asyncio
async def test_sign_certificate_request() -> None:
    """
    Test Sign_Certificate_Request method.
    """

    with open("/tmp/csr.csr", "r") as csr_file:
        csr = csr_file.read()

    if CLUSTER_TYPE == "mssp":
        # Test that certificate signing is not allowed for MSSP
        with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
            await webadm_api_manager.sign_certificate_request(csr)
        assert str(excinfo).startswith(
            "<ExceptionInfo InternalError('Certificate signing not allowed for tenants')"
        )
    else:
        # Test with default expiration (1 year)
        response = await webadm_api_manager.sign_certificate_request(csr)
        assert response

        certificate = x509.load_pem_x509_certificate(
            response.encode("utf-8"), backend=default_backend()
        )
        csr_object = x509.load_pem_x509_csr(
            csr.encode("utf-8"), backend=default_backend()
        )
        assert certificate.subject == csr_object.subject
        assert certificate.public_key() == csr_object.public_key()
        assert (
            round(
                (
                    certificate.not_valid_after_utc - certificate.not_valid_before_utc
                ).total_seconds()
            )
            == 31536000
        )

        # Test with expiration to one day
        response = await webadm_api_manager.sign_certificate_request(csr, expires=1)

        assert response

        certificate = x509.load_pem_x509_certificate(
            response.encode("utf-8"), backend=default_backend()
        )
        csr_object = x509.load_pem_x509_csr(
            csr.encode("utf-8"), backend=default_backend()
        )
        assert certificate.subject == csr_object.subject
        assert certificate.public_key() == csr_object.public_key()
        assert (
            round(
                (
                    certificate.not_valid_after_utc - certificate.not_valid_before_utc
                ).total_seconds()
            )
            == 86400
        )


@pytest.mark.asyncio
async def test_unlock_application_access() -> None:
    """
    Test Unlock_Application_Access method.
    """

    # Test with bad type for application argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.unlock_application_access(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
            "selfreg",
            3600,
        )
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('application type is not UnlockApplication')"
    )

    response = await webadm_api_manager.unlock_application_access(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        UnlockApplication.SELFREG,
        3600,
    )

    assert response


@pytest.mark.asyncio
async def test_update_inventory_item() -> None:
    """
    Test Update_Inventory_Item method.
    """

    # Test with bad type for status argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.update_inventory_items(
            "OTP Token",
            "151147490827268",
            status="Valid",
        )
        # NOSONAR
    assert str(excinfo).startswith(
        EXCEPTION_NOT_RIGHT_TYPE.format("status", "InventoryStatus")
    )

    # Test updating unknown type
    response = await webadm_api_manager.update_inventory_items("Unknown type")
    assert response == 0

    # Test updating all OTP Token type to not active
    response = await webadm_api_manager.update_inventory_items(
        "OTP Token", active=False
    )

    assert response == 6

    # Test updating OTP Token type as lost for only a specific reference
    response = await webadm_api_manager.update_inventory_items(
        "OTP Token", filter_="151147490827268", status=InventoryStatus.LOST
    )

    assert response == 1

    # Test updating OTP Token type as active and valid for only linked tokens
    response = await webadm_api_manager.update_inventory_items(
        "OTP Token",
        filter_="100000000000000001",
        linked=True,
        active=True,
        status=InventoryStatus.VALID,
    )

    assert response == 1


@pytest.mark.skip("Require SMS credit")
@pytest.mark.asyncio
async def test_send_sms() -> None:
    """
    Test Send_SMS method.
    """

    response = await webadm_api_manager.send_sms(SMS_MOBILE, "test")
    assert response

    response = await webadm_api_manager.send_sms(SMS_MOBILE, "test", "from")
    assert response


@pytest.mark.asyncio
async def test_set_client_mode() -> None:
    """
    Test Set_Client_Mode method.
    """

    # Test with bad type for ClientMode argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.set_client_mode("Allowed_Addresses", 2)
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('mode type is not ClientMode')"
    )

    response = await webadm_api_manager.set_client_mode(
        RANDOM_STRING, ClientMode.STEP_DOWN
    )

    assert not response

    response = await webadm_api_manager.set_client_mode(
        "Allowed_Addresses",
        ClientMode.STEP_DOWN,
        timeout=10,
        group=False,
        network=False,
    )

    assert response


@pytest.mark.skipif(CLUSTER_TYPE != "mssp", reason="Only for MSSP")
@pytest.mark.asyncio
async def test_sync_ldap_object() -> None:
    """
    Test Sync_LDAP_Object method.
    """

    # Creating sync OU
    response = await webadm_api_manager.create_ldap_object(
        f"ou=sync,{WEBADM_BASE_DN}",
        {"objectclass": ["organizationalunit"], "ou": "sync"},
    )

    assert response

    # Test with bad type for LDAPSyncObjectType argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        await webadm_api_manager.sync_ldap_object(
            "CN=testuser,CN=Users,DC=suptesting,DC=rcdevs,DC=com",
            attrs={"uid": ["testuser"], "userpassword": ["password"]},
            type_="user",
            uuid="ec1484d3-66b6-44b7-825a-e3c1c39a8305",
        )
        # NOSONAR
    assert str(excinfo).startswith(
        "<ExceptionInfo TypeError('type of type_ is not LDAPSyncObjectType')"
    )

    response = await webadm_api_manager.sync_ldap_object(
        "CN=testuser,CN=Users,DC=suptesting,DC=rcdevs,DC=com",
        attrs={"uid": ["testuser"], "userpassword": ["password"]},
        type_=LDAPSyncObjectType.USER,
        uuid="ec1484d3-66b6-44b7-825a-e3c1c39a8305",
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"ou=sync,{WEBADM_BASE_DN}",
        scope=LDAPSearchScope.ONE,
        attrs=["cn"],
    )

    assert response == {
        "cn=testuser,ou=sync,ou=pyrcdevs,ou=users": {"cn": ["testuser"]}
    }

    response = await webadm_api_manager.sync_ldap_object(
        "CN=testgroup,CN=Users,DC=suptesting,DC=rcdevs,DC=com",
        attrs={"gid": ["testgroup"]},
        type_=LDAPSyncObjectType.GROUP,
        uuid="2dd5fade-c9f3-4766-8be5-21cf424b2c97",
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"ou=sync,{WEBADM_BASE_DN}",
        scope=LDAPSearchScope.ONE,
        attrs=["cn"],
    )

    assert response == {
        f"cn=testgroup,ou=sync,{WEBADM_BASE_DN}".lower(): {
            "cn": [
                "testgroup",
            ],
        },
        f"cn=testuser,ou=sync,{WEBADM_BASE_DN}".lower(): {
            "cn": [
                "testuser",
            ],
        },
    }


@pytest.mark.skipif(CLUSTER_TYPE != "mssp", reason="Only for MSSP")
@pytest.mark.asyncio
async def test_sync_ldap_delete() -> None:
    """
    Test Sync_LDAP_Delete method.
    """

    # Test deleting everything except testuser account
    response = await webadm_api_manager.sync_ldap_delete(
        "CN=Users,DC=suptesting,DC=rcdevs,DC=com",
        ["CN=testuser,CN=Users,DC=suptesting,DC=rcdevs,DC=com"],
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"ou=sync,{WEBADM_BASE_DN}",
        scope=LDAPSearchScope.ONE,
        attrs=["cn"],
    )

    assert response == {
        f"cn=testuser,ou=sync,{WEBADM_BASE_DN}".lower(): {
            "cn": [
                "testuser",
            ],
        },
    }

    # Test deleting everything
    response = await webadm_api_manager.sync_ldap_delete(
        "CN=Users,DC=suptesting,DC=rcdevs,DC=com",
        [""],
    )

    assert response

    response = await webadm_api_manager.search_ldap_objects(
        f"ou=sync,{WEBADM_BASE_DN}",
        scope=LDAPSearchScope.ONE,
        attrs=["cn"],
    )

    assert response == []
