"""This module implements tests for WebADM API Manager."""

import os
import re
import secrets
import string

import pytest

import pyrcdevs
from pyrcdevs import WebADMManager
from pyrcdevs.manager import InternalError
from pyrcdevs.manager.Manager import InvalidParams
from pyrcdevs.manager.WebADMManager import AutoConfirmApplication, AutoConfirmExpiration

REGEX_PARAMETER_DN_NOT_STRING = (
    "<ExceptionInfo InvalidParams('Parameter dn not String') tblen=3>"
)

REGEX_VERSION_NUMBER = r"[0-9.]+"
RANDOM_STRING = "".join(
    secrets.choice(string.ascii_letters + string.digits) for _ in range(10)
)
DN_PYRCDEVS_BASE_DN = "ou=pyrcdevs,o=root"
LIST_STATUS_SERVERS_KEYS = ["ldap", "mail", "pki", "session", "sql"]
LIST_STATUS_WEB_TYPES = {
    "webapps": ["HelpDesk", "OpenID", "PwReset", "SelfDesk", "SelfReg"],
    "websrvs": ["OpenOTP", "SMSHub", "SpanKey"],
}

webadm_host = os.environ["WEBADM_HOST"]
webadm_api_username = os.environ["WEBADM_API_USERNAME"]
webadm_api_password = os.environ["WEBADM_API_PASSWORD"]

webadm_api_manager = WebADMManager(
    webadm_host, "443", webadm_api_username, webadm_api_password, False
)


def test_create_ldap_object() -> None:
    # Test creating object with malformed DN
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.create_ldap_object(
            RANDOM_STRING,
            {
                "objectclass": ["person", "inetorgperson"],
                "sn": "testfail",
                "cn": "testfail",
                "uid": "testfail",
                "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
            },
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
    )

    # Test creating object in non existing container
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.create_ldap_object(
            f"cn=testfail,ou={RANDOM_STRING},o=root",
            {
                "objectclass": ["person", "inetorgperson"],
                "sn": "testfail",
                "cn": "testfail",
                "uid": "testfail",
                "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
            },
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not create LDAP object 'cn=testfail,ou={RANDOM_STRING},o=root' "
        f'(No such object)") tblen=3>'
    )

    # Test creating testfail object with no attribute information
    create_ldap_object_response = webadm_api_manager.create_ldap_object(
        f"cn=testfail,{DN_PYRCDEVS_BASE_DN}",
        {},
    )
    assert not create_ldap_object_response

    """
    Test Create_LDAP_Object method
    """
    # Test creating testuser1 object
    create_ldap_object_response = webadm_api_manager.create_ldap_object(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}",
        {
            "objectclass": ["person", "inetorgperson", "posixAccount"],
            "sn": "testuser1",
            "cn": "testuser1",
            "uid": "testuser1",
            "uidnumber": 500,
            "gidnumber": 100,
            "homedirectory": "/home/testuser1",
            "loginshell": "/bin/bash",
            "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
        },
    )
    assert create_ldap_object_response

    """
    Test Create_LDAP_Object method
    """
    # Test creating testuser1 object
    create_ldap_object_response = webadm_api_manager.create_ldap_object(
        f"cn=testuser2,{DN_PYRCDEVS_BASE_DN}",
        {
            "objectclass": ["person", "inetorgperson", "posixAccount"],
            "sn": "testuser2",
            "cn": "testuser2",
            "uid": "testuser2",
            "uidnumber": 501,
            "gidnumber": 100,
            "homedirectory": "/home/testuser2",
            "loginshell": "/bin/bash",
            "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
        },
    )
    assert create_ldap_object_response

    # Test creating again testuser1 object
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.create_ldap_object(
            f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}",
            {
                "objectclass": ["person", "inetorgperson"],
                "sn": "testuser1",
                "cn": "testuser1",
                "uid": "testuser1",
                "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
            },
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=testuser1,{DN_PYRCDEVS_BASE_DN}' already exist\") tblen=3>"
    )

    # Test creating unactivated object
    create_ldap_object_response = webadm_api_manager.create_ldap_object(
        f"cn=unactivated,{DN_PYRCDEVS_BASE_DN}",
        {
            "objectclass": ["person", "inetorgperson"],
            "sn": "unactivated",
            "cn": "unactivated",
            "uid": "unactivated",
            "userpassword": "{SSHA}La7dfFrmC/ee3odOmFJ8bSMVy/Brmv+Y",  # NOSONAR
        },
    )
    assert create_ldap_object_response

    # Test creating testgroup1 object
    create_ldap_object_response = webadm_api_manager.create_ldap_object(
        f"cn=testgroup1,{DN_PYRCDEVS_BASE_DN}",
        {
            "objectclass": ["groupofnames", "posixgroup"],
            "cn": "testgroup1",
            "gidnumber": 100,
        },
    )
    assert create_ldap_object_response

    # Test creating testgroup2 object
    create_ldap_object_response = webadm_api_manager.create_ldap_object(
        f"cn=testgroup2,{DN_PYRCDEVS_BASE_DN}",
        {
            "objectclass": ["groupofnames", "posixgroup"],
            "cn": "testgroup2",
            "gidnumber": 101,
        },
    )
    assert create_ldap_object_response


def test_activate_ldap_object() -> None:
    """
    Test Activate_LDAP_Object method.
    """
    # Test to activate non existing object

    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.activate_ldap_object(f"cn=Not_exist_{RANDOM_STRING},o=root")
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=Not_exist_{RANDOM_STRING},o=root' does not exist\") "
        f"tblen=3>"
    )

    # Test to activate providing a malformed DN
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.activate_ldap_object(RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
    )

    # Test to activate existing account
    activate_ldap_object_response = webadm_api_manager.activate_ldap_object(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}"
    )
    assert activate_ldap_object_response

    # Test to activate existing account already activated
    activate_ldap_object_response = webadm_api_manager.activate_ldap_object(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}"
    )
    assert not activate_ldap_object_response

    # Test to activate existing group
    activate_ldap_object_response = webadm_api_manager.activate_ldap_object(
        f"cn=testgroup1,{DN_PYRCDEVS_BASE_DN}"
    )
    assert activate_ldap_object_response

    # Test to activate existing group
    activate_ldap_object_response = webadm_api_manager.activate_ldap_object(
        f"cn=testgroup2,{DN_PYRCDEVS_BASE_DN}"
    )
    assert activate_ldap_object_response

    # Test to activate existing group already activated
    activate_ldap_object_response = webadm_api_manager.activate_ldap_object(
        f"cn=testgroup1,{DN_PYRCDEVS_BASE_DN}"
    )
    assert not activate_ldap_object_response


def test_cert_auto_confirm() -> None:
    """
    Test Cert_Auto_Confirm method.
    """
    # Test with bad type for expires argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.cert_auto_confirm(
            1, AutoConfirmApplication.OPENOTP
        )  # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('application type is not AutoConfirmExpiration') tblen=2>"
    )

    # Test with bad type for application argument.
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.cert_auto_confirm(
            AutoConfirmExpiration.E1, "OpenOTP"
        )  # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('application type is not AutoConfirmApplication') tblen=2>"
    )

    # Test with bad type for addresses argument.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.cert_auto_confirm(
            AutoConfirmExpiration.E1, addresses=1
        )  # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo InvalidParams('Parameter addresses not String') tblen=3>"
    )

    # Test setting 10 minutes for expires and a bad address format for addresses
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.cert_auto_confirm(
            AutoConfirmExpiration.E10, addresses="bad address format"
        )
    assert (
        str(excinfo)
        == "<ExceptionInfo InternalError('Invalid IP address or mask') tblen=3>"
    )

    # Test setting 1 minute for expires
    cert_auto_confirm_response = webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E1
    )
    assert cert_auto_confirm_response

    # Test setting 10 minutes for expires, and OpenOTP as application
    cert_auto_confirm_response = webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E10, AutoConfirmApplication.OPENOTP
    )
    assert cert_auto_confirm_response

    # Test setting 10 minutes for expires, and 127.0.0.1/24 for addresses
    cert_auto_confirm_response = webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E10, addresses="127.0.0.1/24"
    )
    assert cert_auto_confirm_response

    # Test setting 10 minutes for expires, OpenOTP for application, and 127.0.0.1/24 for addresses
    cert_auto_confirm_response = webadm_api_manager.cert_auto_confirm(
        AutoConfirmExpiration.E10,
        application=AutoConfirmApplication.OPENOTP,
        addresses="127.0.0.1/24",
    )
    assert cert_auto_confirm_response


def test_check_ldap_object() -> None:
    """
    Test Check_LDAP_Object method.
    """
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.check_ldap_object(1)
        # NOSONAR
    assert str(excinfo) == REGEX_PARAMETER_DN_NOT_STRING

    # Test with malformed DN.
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_ldap_object(RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
    )

    # Test with non existing DN object
    check_ldap_object_response = webadm_api_manager.check_ldap_object(
        f"cn={RANDOM_STRING},{DN_PYRCDEVS_BASE_DN}"
    )
    assert not check_ldap_object_response

    # Test with existing DN object
    check_ldap_object_response = webadm_api_manager.check_ldap_object(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}"
    )
    assert check_ldap_object_response


def test_check_user_active() -> None:
    """
    Test Check_User_Active method.
    """
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.check_user_active(1)
        # NOSONAR
    assert str(excinfo) == REGEX_PARAMETER_DN_NOT_STRING

    # Test with malformed DN.
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_user_active(RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
    )

    # Test with non existing DN object
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_user_active(
            f"cn={RANDOM_STRING},{DN_PYRCDEVS_BASE_DN}"
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object 'cn={RANDOM_STRING},{DN_PYRCDEVS_BASE_DN}' "
        f'(No such object)") tblen=3>'
    )

    # Test with existing activated user object (testuser1)
    check_ldap_object_response = webadm_api_manager.check_user_active(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}"
    )
    assert check_ldap_object_response

    # Test with existing unactivated user object (unactivated)
    check_ldap_object_response = webadm_api_manager.check_user_active(
        f"cn=unactivated,{DN_PYRCDEVS_BASE_DN}"
    )
    assert not check_ldap_object_response


def test_check_user_password() -> None:
    """
    Test Check_User_Password method.
    """
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.check_user_password(1, "")
        # NOSONAR
    assert str(excinfo) == REGEX_PARAMETER_DN_NOT_STRING

    # Test with wrong password type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.check_user_password(f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}", 1)
        # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo InvalidParams('Parameter password not String') tblen=3>"
    )

    # Test with malformed DN.
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_user_password(RANDOM_STRING, "password")
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
    )

    # Test with non existing DN object
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_user_password(
            f"cn={RANDOM_STRING},{DN_PYRCDEVS_BASE_DN}",
            "password",
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn={RANDOM_STRING},{DN_PYRCDEVS_BASE_DN}' "
        f'does not exist") tblen=3>'
    )

    # Test with existing DN object, but a wrong password
    check_user_password_response = webadm_api_manager.check_user_password(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}",
        "wrong password",
    )
    assert not check_user_password_response

    # Test with existing DN object, and the right password
    check_user_password_response = webadm_api_manager.check_user_password(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}",
        "password",
    )
    assert check_user_password_response


def test_clear_caches() -> None:
    """
    Test Clear_Caches method.
    """
    # Test with no argument provided.
    clear_caches_response = webadm_api_manager.clear_caches()
    assert clear_caches_response

    # Test with wrong type_ type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.clear_caches(1, 1)  # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo InvalidParams('Parameter type not String') tblen=3>"
    )

    # Test with wrong tenant type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.clear_caches("test", 1)  # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo InvalidParams('Parameter tenant not String') tblen=3>"
    )

    # Test with non existing type_.
    clear_caches_response = webadm_api_manager.clear_caches(
        "nonexistingtype"
    )  # NOSONAR
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
        clear_caches_response = webadm_api_manager.clear_caches(type_str)  # NOSONAR
        assert clear_caches_response


def test_server_status() -> None:
    """
    Test Server_Status method.
    """
    # Test with no argument provided. It must return only general status and version.
    server_status_response = webadm_api_manager.server_status()
    keys = list(server_status_response.keys())
    keys.sort()
    assert keys == ["status", "version"]
    assert isinstance(server_status_response["status"], bool)
    assert re.compile(REGEX_VERSION_NUMBER).search(server_status_response["version"])

    # Test with all arguments provided (all set to False). It must also return only general status and version.
    server_status_response = webadm_api_manager.server_status(False, False, False)
    keys = list(server_status_response.keys())
    keys.sort()
    assert keys == ["status", "version"]
    assert isinstance(server_status_response["status"], bool)
    assert re.compile(REGEX_VERSION_NUMBER).search(server_status_response["version"])

    # Test with all arguments provided (set to True). It must return general status and version,
    # and status of servers, webapps, and websrvs.
    server_status_response = webadm_api_manager.server_status(True, True, True)

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


def test_set_user_data() -> None:
    """
    Test Set_User_Data method.
    """
    response = webadm_api_manager.set_user_data(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}",
        {
            "OpenOTP.EmergOTP": "4QrcOUm6Wau+VuBX8g+IPmZy2wOXWf+aAAA=",
            "SpanKey.PublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6UxOwHGPE0+O3bxOV64XNzmKPZTvW6O8zhxigi/3"
            "L2vWvLKyY0W9A5aSmSGffL+2+NotXjRYHOg7Tz/Dx6gXP8sJzUzsVxWo9hSKorajpS6Cvs+XD1ae5p7quU25Q"
            "xRcVz3h+kpPxAIXhQpGDMmfrtpIRCdCO/1y4uri6jKZALY87XcKPFauVCcxSkrg37QILeBU7LhsHRJCRlkLAu"
            "hJ6rtrig1soCqYrH0Vw779rZBXbQNbKVuMFbmG3PmCbs5m/jC29Z0aQMEVs4DhETxBqyqSaqCSdqfI7WGrOjh"
            "L6RvtYAHnc2xjlijV6phOxicvwMt9Q9x9CKXEDyo5B6DNwIDAQAB",
            "SpanKey.KeyType": "c3NoLXJzYQ==",
            "OpenOTP.TokenType": "VE9UUA==",
            "OpenOTP.TokenKey": "vkg8+O132G75VYUqHprO/CT7Gdo=",
            "OpenOTP.TokenState": "MA==",
            "OpenOTP.TokenSerial": "MGEwZTI2MjgxYmRmOWYwOA==",
            "OpenOTP.TokenModel": "c2Ftc3VuZyBTTS1HOTkxQiAoQmVub8OudCdzIFMyMSk=",
            "OpenOTP.TokenID": "QU5EOmQ2TlRjN2NPUWUtQWdNMU9kUjM4VkE6QVBBOTFiRURpYWxBd2RsdU50aXNHN1NrcDgxR3ZhZkp2S1VlWVp"
                               "mOTVtMG9Xd1lkODJDdE5DdkJ6M1ZCRFE0R2xKdjF2ZU0xeUxjWlFmRndNNE9sZ2JrV2JHVkg5SWNNaGpzOUhQQT"
                               "dBeWNRVk9tMFE1dkpmZDU0RXZhck83dGFaZnotMHF4Uk5lOWc=",
        },
    )
    assert response


def test_set_user_attrs() -> None:
    """
    Test Set_User_Attrs method.
    """
    response = webadm_api_manager.set_user_attrs(
        f"cn=testuser1,{DN_PYRCDEVS_BASE_DN}",
        {
            "usercertificate": [
                "MIIGijCCBHKgAwIBAgIRAP+NV0Vn8TNb6UAXVkMerIMwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAwwTV2ViQURNIENBICM4NzQxNj"
                "ExNzAeFw0yNDEyMjAxNjA5NTBaFw0yNTEyMjAxNjA5NTBaMIGWMRowGAYDVQQDDBFEZWZhdWx0XHRlc3R1c2VyMTEZMBcGCgmSJomT"
                "8ixkAQEMCXRlc3R1c2VyMTEXMBUGCgmSJomT8ixkARkWB0RlZmF1bHQxFzAVBgNVBAoMDlJDRGV2cyBTdXBwb3J0MRcwFQYDVQRhDA"
                "5WQVRMVS0wMDAwMDAwMDESMBAGA1UEBAwJdGVzdHVzZXIxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzvZu5XWFDNiz"
                "tin2srfW1gM1IlN/Y8AGXuhI9EK4glqqFFrCOr3nb/Qc5RfLsuiOqG84SVOW6RoIaqO+qa17tXgPa9VQrpdsmEGGD/0275QwEiU0Ke"
                "52j3nXkKSPhfcVEsXBb73SUc1O569Bajp6b9NubhrgYX7+0VegQTw6uPfeNYHI3OrRSiT5rNeQwR869viSYGsUvTjIGepgIRlOxLoz"
                "ddIP44yPHf0nC+3sbrfmuHT1l4Qc2NepzG1jnJ833Ogf/G4ZvMCYL774pRtYuLuVC2pn0aGuYmvxpJkCGSVWeZlY2Kf2Q2dxU4ubZM"
                "boZKwWnbrFYgOedgxmLOmCLcj5Vjd8EdxBd08uuyqLslqO4kG0JXlZGK8s/CwUTYPlooRX4yvIFywGgxQ/RvuNS/POee5nkfTSXIlK"
                "KwIOv1Bf4fNTnqVDjv4EM5jjvTtsYl48F0vBzt/XJXXzvRxdRHMjUg2+/iDEgHihuDPK5cSlPM4lTKaKRQ4nxS7T+UPjEVIMFfamQ8"
                "Nq8FoZkkTA9VkbxJvyPHPaKaWK0espCChDbmCdhj77eKZfZyLpr5/PZmx3AHx+hh9YnXLpsE694xvV3KqcNeGTqcmgCsxvAlyzFj1d"
                "l4W8mcO9c//lDfi1dQ7pxO7/2GqQuoFEhfVLWU92vu8Ro5PGAaleFKWBxzUCAwEAAaOCAUgwggFEMAsGA1UdDwQEAwIF4DApBgNVHS"
                "UEIjAgBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcUAgIwHQYDVR0OBBYEFGPtlNCp8pTRtF/NntUOeTDwceckMIGVBggrBgEF"
                "BQcBAQSBiDCBhTBHBggrBgEFBQcwAoY7aHR0cDovL2Nsb3VkLnJjZGV2cy5jb20vY2EvemZkZ2psc3pwZHpsYy9jYWNlcnQvP2Zvcm"
                "1hdD1kZXIwOgYIKwYBBQUHMAGGLmh0dHA6Ly9jbG91ZC5yY2RldnMuY29tL2NhL3pmZGdqbHN6cGR6bGMvb2NzcC8wPgYDVR0fBDcw"
                "NTAzoDGgL4YtaHR0cDovL2Nsb3VkLnJjZGV2cy5jb20vY2EvemZkZ2psc3pwZHpsYy9jcmwvMBMGCysGAQQBgo45AwEBBARVU0VSMA"
                "0GCSqGSIb3DQEBCwUAA4ICAQB6dts21Zx61Hrapfm6TgnNqleAbdPhsHn06JjDfrKMKvZGplPhqWj0zj3G4yS8CcgY9ySdi3i6ZCCf"
                "dffJ6uLc+6Rw+borEvUJyn1D2SZR1g9I3BT27mYdsm7+u17QTzqrabHO59Emw/BoGUPv1Ikn7T7vidTFHhbzsUf4bzu2jI3zV8Q76x"
                "QwsQ+2ER87AHKtr4Y0TARmOyQGOrQu1D+32aWLU83XWZrzqbcUlVpRUYtyFgiUitmiIP7EKilLCkXBFLY726zU1M5ctS7PWKzuOpvR"
                "T7Jn0mM1qyqvDufLyn+333kjkx97Au33hqDF8A4k7kHyb4qzJkMRE5cCCDmubI/3o5IVdDVpuyI2bQlwYCj0IJvrm5OqOLcRewXEb+"
                "lACy1K0408FmKtcGGIEbXGx1KwZp0gaCg9cd++BfL1XDSjpwmBt43O9CzOv60V4ufG99s/63MMYKVLQNSS0uqUpw8nnXPKlNbBwFOK"
                "Dy4wAnQskDLSD6dKvw5SEcpXk7U9fQRMTIRQ88kVRmvcqXC6lieA4nII5Mat0TaN8omOtTj1Q9LwhF6WagRrijFE3ihGQDbXXAT6tK"
                "tuL/tLW2BKwa2u66WZu+zA4E9QNnhsdFyYkpqE4xElu7YbCcc8ncSTX4oiRtmTvpfgvKGlVHeg5KP+3OaKuG4P7UvHIEMiEw=="
            ],
        },
    )
    assert response
