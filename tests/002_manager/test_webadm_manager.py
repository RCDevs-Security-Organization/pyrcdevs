"""This module implements tests for WebADM API Manager."""

import base64
import json
import re
import secrets
from encodings.punycode import selective_find
from http.client import responses

import pytest
from cffi.model import unknown_type

import pyrcdevs
from pyrcdevs import WebADMManager
from pyrcdevs.constants import MSG_NOT_RIGHT_TYPE, REGEX_BASE64
from pyrcdevs.manager import InternalError
from pyrcdevs.manager.Manager import InvalidParams
from pyrcdevs.manager.WebADMManager import (
    AutoConfirmApplication,
    AutoConfirmExpiration,
    ConfigObjectApplication,
    ConfigObjectType,
    EventLogApplication,
    LicenseProduct,
)
from tests.constants import (
    CLUSTER_TYPE,
    DEFAULT_PASSWORD,
    GROUP_OBJECTCLASS,
    LDAP_BASE_DN,
    LIST_STATUS_SERVERS_KEYS,
    LIST_STATUS_WEB_TYPES,
    OPENOTP_PUSHID,
    OPENOTP_TOKENKEY,
    RANDOM_STRING,
    REGEX_LOGTIME_TIME,
    REGEX_PARAMETER_DN_NOT_STRING,
    REGEX_VERSION_NUMBER,
    TESTER_NAME,
    USER_CERT_PATH,
    WEBADM_API_PASSWORD,
    WEBADM_API_USERNAME,
    WEBADM_BASE_DN,
    WEBADM_HOST,
    LIST_USER_ACCOUNT_LDAP_AD,
    LIST_USER_ACCOUNT_LDAP_SLAPD,
    DICT_USER_OBJECTCLASS,
)

webadm_api_manager = WebADMManager(
    WEBADM_HOST, WEBADM_API_USERNAME, WEBADM_API_PASSWORD, 443, False
)


uid_numbers = {}


def get_random_uid_number():
    list_uid_numbers = list(uid_numbers.values())
    random_uid_number = 600 + secrets.randbits(10)
    while random_uid_number in list_uid_numbers:
        random_uid_number = 600 + secrets.randbits(10)
    return random_uid_number


def _test_malformed_dns(method, *args) -> None:
    # Test with wrong DN type.
    with pytest.raises(InvalidParams) as excinfo:
        # noinspection PyTypeChecker
        if args:
            method(1, *args)
        else:
            method(1)
        # NOSONAR
    assert str(excinfo) == REGEX_PARAMETER_DN_NOT_STRING

    # Test to get user attribute of a non existing object
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        if args:
            method(f"CN=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}", *args)
        else:
            method(f"CN=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}")
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'CN=Not_exist_{RANDOM_STRING},o=root' does not exist\") "
        f"tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'CN=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}' "
        'does not exist") tblen=3>'
    )

    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        if args:
            method(RANDOM_STRING, *args)
        else:
            method(RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
        f"NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of:"
        f"\\t'{RANDOM_STRING}')\") tblen=3>"
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


def test_create_ldap_object() -> None:
    """
    Test Create_LDAP_Object method
    """
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
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' "
        f"(0000208F: NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match "
        f"of:\\t'{RANDOM_STRING}')\") tblen=3>"
    )

    # Test creating object in non existing container
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.create_ldap_object(
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
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not create LDAP object 'CN=testfail,OU={RANDOM_STRING},"
        f"{WEBADM_BASE_DN}' (No such object)\") tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not create LDAP object 'CN=testfail,OU={RANDOM_STRING},"
        f"{WEBADM_BASE_DN[:47]}..., data 0, best match of:\\t'{LDAP_BASE_DN}')\") tblen=3>"
        or str(excinfo.value)
        == f"Could not create LDAP object 'CN=testfail,OU={RANDOM_STRING},{WEBADM_BASE_DN}' "
        f"(0000208D: NameErr: DSID-0310028D, problem 2001 (NO_OBJECT), data 0, best match "
        f"of:\t'{LDAP_BASE_DN}')"
    )

    # Test creating testfail object with no attribute information
    response = webadm_api_manager.create_ldap_object(
        f"CN=testfail,{WEBADM_BASE_DN}",
        {},
    )
    assert not response

    # Test creating testuserapi1 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", 100
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi2 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2", 100
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi3 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3"
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi4 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4"
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating again testuserapi1 object
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        user_attributes = generate_user_attrs(f"u_{CLUSTER_TYPE}_api_1", 100)
        webadm_api_manager.create_ldap_object(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
            user_attributes,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,"
        f"{WEBADM_BASE_DN}' already exist\") tblen=3>"
    )

    # Test creating unactivated object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact"
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testgroup1 object
    group_attributes = generate_group_attrs(
        f"g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", 100
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        group_attributes,
    )
    assert response

    # Test creating testgroup2 object
    group_attributes = generate_group_attrs(
        f"g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2", 101
    )
    response = webadm_api_manager.create_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}",
        group_attributes,
    )
    assert response

    with open("/tmp/uidnumbers.json", "w") as json_file:
        json_file.write(json.dumps(uid_numbers))


def test_activate_ldap_object() -> None:
    """
    Test Activate_LDAP_Object method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.activate_ldap_object)

    # Test to activate existing account
    response = webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account
    response = webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account
    response = webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account already activated
    response = webadm_api_manager.activate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )
    assert not response

    # Test to activate existing group
    response = webadm_api_manager.activate_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing group
    response = webadm_api_manager.activate_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing group already activated
    response = webadm_api_manager.activate_ldap_object(
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )
    assert not response


def test_deactivate_ldap_object() -> None:
    """
    Test Deactivate_LDAP_Object method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.deactivate_ldap_object)

    # Test to deactivate an activated account
    response = webadm_api_manager.deactivate_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    if "metadata" not in WEBADM_HOST:
        with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
            webadm_api_manager.deactivate_ldap_object(
                f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
            )
        assert (
            str(excinfo)
            == f"<ExceptionInfo InternalError(\"Object 'CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,"
            f"{WEBADM_BASE_DN}' is not an activated user or group\") tblen=3>"
        )


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
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
        "NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of"
        f":\\t'{RANDOM_STRING}')\") tblen=3>"
    )

    # Test with non existing DN object
    check_ldap_object_response = webadm_api_manager.check_ldap_object(
        f"CN={RANDOM_STRING},{WEBADM_BASE_DN}"
    )
    assert not check_ldap_object_response

    # Test with existing DN object
    check_ldap_object_response = webadm_api_manager.check_ldap_object(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
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

    if "metadata" not in WEBADM_HOST:
        # Test with malformed DN.
        with pytest.raises(InternalError) as excinfo:
            webadm_api_manager.check_user_active(RANDOM_STRING)
        assert (
            str(excinfo)
            == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
            or str(excinfo)
            == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
            "NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of"
            f":\\t'{RANDOM_STRING}')\") tblen=3>"
        )

        # Test with non existing DN object
        with pytest.raises(InternalError) as excinfo:
            webadm_api_manager.check_user_active(f"CN={RANDOM_STRING},{WEBADM_BASE_DN}")
        assert (
            str(excinfo)
            == f"<ExceptionInfo InternalError(\"Could not read LDAP object 'CN={RANDOM_STRING},{WEBADM_BASE_DN}' "
            f'(No such object)") tblen=3>'
            or str(excinfo)
            == f"<ExceptionInfo InternalError(\"Could not read LDAP object 'CN={RANDOM_STRING},"
            f"{WEBADM_BASE_DN[:61]}..., data 0, best match of:\\t'{WEBADM_BASE_DN}')\") tblen=3>"
        )

        # Test with existing activated user object (testuserapi1)
        response = webadm_api_manager.check_user_active(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
        )
        assert response

        # Test with existing unactivated user object (unactivated)
        response = webadm_api_manager.check_user_active(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_unact,{WEBADM_BASE_DN}"
        )
        assert not response


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
        webadm_api_manager.check_user_password(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}", 1
        )
        # NOSONAR
    assert (
        str(excinfo)
        == "<ExceptionInfo InvalidParams('Parameter password not String') tblen=3>"
    )

    # Test with malformed DN.
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_user_password(RANDOM_STRING, DEFAULT_PASSWORD)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' "
        f"(0000208F: NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match "
        f"of:\\t'{RANDOM_STRING}')\") tblen=3>"
    )

    # Test with non existing DN object
    with pytest.raises(InternalError) as excinfo:
        webadm_api_manager.check_user_password(
            f"CN={RANDOM_STRING},{WEBADM_BASE_DN}",
            DEFAULT_PASSWORD,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'CN={RANDOM_STRING},{WEBADM_BASE_DN}' "
        f'does not exist") tblen=3>'
    )

    # Test with existing DN object, but a wrong password
    check_user_password_response = webadm_api_manager.check_user_password(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        "wrong password",
    )
    assert not check_user_password_response

    # Test with existing DN object, and the right password
    check_user_password_response = webadm_api_manager.check_user_password(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        DEFAULT_PASSWORD,
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
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        {
            "OpenOTP.EmergOTP": "4QrcOUm6Wau+VuBX8g+IPmZy2wOXWf+aAAA=",
            "SpanKey.PublicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq6UxOwHGPE0+O3bxOV64XNzmKPZTvW6O8zhxigi/3"
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


def test_count_activated_hosts() -> None:
    """
    Test Count_Activated_Hosts method.
    """
    # Test with wrong type for product parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.count_activated_hosts("OpenOTP")
    assert (
        str(excinfo)
        == f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('product', 'LicenseProduct')}') tblen=2>"
    )

    # Test with no parameter
    response = webadm_api_manager.count_activated_hosts()
    assert isinstance(response, int) and response >= 0

    # Test with parameter set to LicenseProduct.OPENOTP
    response = webadm_api_manager.count_activated_hosts(LicenseProduct.OPENOTP)
    assert isinstance(response, int) and response >= 0


def test_count_activated_users() -> None:
    """
    Test Count_Activated_Users method.
    """
    # Test with wrong type for product parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.count_activated_users("OpenOTP")
    assert (
        str(excinfo)
        == f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('product', 'LicenseProduct')}') tblen=2>"
    )

    # Test with no parameter
    response = webadm_api_manager.count_activated_users()
    assert isinstance(response, int) and response >= 0

    # Test with parameter set to LicenseProduct.OPENOTP
    response = webadm_api_manager.count_activated_users(LicenseProduct.OPENOTP)
    assert isinstance(response, int) and response >= 0


def test_count_domain_users() -> None:
    """
    Test Count_Domain_Users method.
    """
    # Test with unknown domain
    response = webadm_api_manager.count_domain_users(RANDOM_STRING)
    assert not response

    # Test with existing domain
    all_users = webadm_api_manager.count_domain_users("Default")
    assert isinstance(all_users, int) and all_users >= 0

    # Test with existing domain and explicitly requesting all users
    all_users2 = webadm_api_manager.count_domain_users("Default", False)
    assert isinstance(all_users2, int) and all_users == all_users2

    # Test with existing domain and requesting only activated users
    activated_users = webadm_api_manager.count_domain_users("Default", True)
    assert (
        isinstance(activated_users, int)
        and activated_users >= 0
        and (
            activated_users != all_users
            or ("metadata" in WEBADM_HOST and activated_users == all_users)
        )
    )


def test_set_user_attrs() -> None:
    """
    Test Set_User_Attrs method.
    """
    with open(USER_CERT_PATH, "rb") as user_cert_file:
        user_cert = user_cert_file.read()
    response = webadm_api_manager.set_user_attrs(
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
    response = webadm_api_manager.set_user_attrs(
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


def test_get_config_objects() -> None:
    """
    Test Get_Config_Objects method.
    """
    # Test to get config using wrong type for type_ parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.get_config_objects("clients")
    assert (
        str(excinfo)
        == f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('type_', 'ConfigObjectType')}') tblen=2>"
    )

    # Test to get config using wrong type for application parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.get_config_objects(
            ConfigObjectType.CLIENTS, application="openotp"
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('application', 'ConfigObjectApplication')}') tblen=2>"
    )

    # Test if getting clients objects with settings parameter not provided returns a list
    response = webadm_api_manager.get_config_objects(ConfigObjectType.CLIENTS)
    assert isinstance(response, list)

    # Test if getting clients objects with settings parameter set explicitly to qFalse returns a list
    response = webadm_api_manager.get_config_objects(
        ConfigObjectType.CLIENTS, settings=False
    )
    assert isinstance(response, list)

    # Test if getting clients objects with settings parameter set True returns a dictionary
    response = webadm_api_manager.get_config_objects(
        ConfigObjectType.CLIENTS, settings=True
    )
    assert isinstance(response, dict)

    # Test if getting clients objects with settings parameter set True, and application set, returns a dictionary
    response = webadm_api_manager.get_config_objects(
        ConfigObjectType.CLIENTS,
        settings=True,
        application=ConfigObjectApplication.OPENOTP,
    )
    assert isinstance(response, dict)


def test_get_event_logs() -> None:
    """
    Test Get_Event_Logs method.
    """
    # Test to get event logs using wrong type for application parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.get_event_logs("openotp")
    assert (
        str(excinfo)
        == f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('application', 'EventLogApplication')}') tblen=2>"
    )
    # Test to get event logs using max value below 1
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.get_event_logs(EventLogApplication.OPENOTP, max_=0)
    assert (
        str(excinfo)
        == "<ExceptionInfo TypeError('max is not a positive int!') tblen=2>"
    )
    # Test to get event logs for a malformed DN
    response = webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP, max_=1, dn=RANDOM_STRING
    )
    assert response == []

    # Test to get event logs for a non existing DN
    response = webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP, max_=1, dn=f"CN={RANDOM_STRING},{WEBADM_BASE_DN}"
    )
    assert response == []

    # Test to get event logs for an existing DN without any authentication
    response = webadm_api_manager.get_event_logs(
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
        user_w_auth = f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_cp_allowed,{WEBADM_BASE_DN.replace('OU=pyrcdevs,', '')}"

    response = webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
        max_=1,
        dn=user_w_auth,
    )
    assert isinstance(response, list)
    assert len(response) == 1

    # Test to get all event logs for an existing DN with authentications
    response = webadm_api_manager.get_event_logs(
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
    response = webadm_api_manager.get_event_logs(
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


def test_get_license_details() -> None:
    """
    Test Get_License_Details method.
    """
    # Test to get license details using wrong type for product parameter
    with pytest.raises(TypeError) as excinfo:
        # noinspection PyTypeChecker
        webadm_api_manager.get_license_details("openotp")
    assert (
        str(excinfo)
        == f"<ExceptionInfo TypeError('{MSG_NOT_RIGHT_TYPE.format('product', 'LicenseProduct')}') tblen=2>"
    )

    # Test to get license details for all products
    response = webadm_api_manager.get_license_details()
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
    response = webadm_api_manager.get_license_details(LicenseProduct.OPENOTP)
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
    response = webadm_api_manager.get_license_details(LicenseProduct.SPANKEY)
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


def test_get_random_bytes() -> None:
    """
    Test Get_Random_Bytes method.
    """
    # Test for non positive integer
    with pytest.raises(pyrcdevs.manager.Manager.InvalidParams) as excinfo:
        webadm_api_manager.get_random_bytes(-1)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InvalidParams('Parameter length not Integer') tblen=3>"
    )

    # Test that different returned random bytes have expected length
    for length in [1, 10, 100, 1000, 10000]:
        response = webadm_api_manager.get_random_bytes(length)
        assert re.compile(REGEX_BASE64).search(response)
        assert len(base64.b64decode(response)) == length


def test_get_user_attrs() -> None:
    """
    Test Get_User_Attrs method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_attrs)

    response = webadm_api_manager.get_user_attrs(
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
        + (["samaccountname", "name"] if CLUSTER_TYPE in ("normal", "metadata") else ["uid"])
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
    response = webadm_api_manager.get_user_attrs(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        ["nonexistingattribute"],
    )
    assert response == []

    # Test for uidnumber and gidnumber
    response = webadm_api_manager.get_user_attrs(
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


def test_get_user_dn() -> None:
    """
    Test Get_User_DN method.
    """
    # Test with unknown domain
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_dn(RANDOM_STRING, RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Domain '{RANDOM_STRING}' not existing\") tblen=3>"
    )

    # Test with unknown user
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_dn(RANDOM_STRING, "Domain_Enabled")
    exception_str = str(excinfo)
    assert (
        exception_str
        == "<ExceptionInfo InternalError('User not found Domain_Enabled\\\\"
        + rf"{RANDOM_STRING}') tblen=3>"
    )

    # Test existing user
    response = webadm_api_manager.get_user_dn(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", "Domain_Enabled"
    )
    assert (
        response.lower()
        == f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )


def test_get_user_domains() -> None:
    """
    Test Get_User_Domains method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_domains)

    # Test existing user
    response = webadm_api_manager.get_user_domains(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )
    assert isinstance(response, list)
    assert len(response) > 0


def test_get_user_groups() -> None:
    """
    Test Get_User_Groups method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_groups, "Domain_Enabled")

    # Test with unknown domain
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_groups(
            f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
            RANDOM_STRING,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Domain '{RANDOM_STRING}' not existing\") tblen=3>"
    )

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_groups(unknown_user_dn, "Domain_Enabled")
    exception_str = str(excinfo)
    assert (
        exception_str
        == f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\") tblen=3>"
    )

    response = webadm_api_manager.get_user_groups(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        "Domain_Enabled",
    )
    assert isinstance(response, list)
    list_groups_lower = [g.lower() for g in response]
    assert list_groups_lower == [
        f"CN=g_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    ]


def test_get_user_data() -> None:
    """
    Test Get_User_Data method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_data)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_data(unknown_user_dn)
    exception_str = str(excinfo)
    assert (
        exception_str
        == f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\") tblen=3>"
    )

    # Test for all existing data
    response = webadm_api_manager.get_user_data(
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
    response = webadm_api_manager.get_user_data(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        [f"{RANDOM_STRING}.{RANDOM_STRING}"],
    )
    assert response == []

    # Test for 2 existing data
    response = webadm_api_manager.get_user_data(
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


def test_get_user_certificates() -> None:
    """
    Test Get_User_Certificates method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_certificates)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_certificates(unknown_user_dn)
    exception_str = str(excinfo)
    assert (
        exception_str
        == f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\") tblen=3>"
    )

    # Test existing user without certificates
    response = webadm_api_manager.get_user_certificates(
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
    response = webadm_api_manager.get_user_certificates(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )
    response.sort()
    expected_certs = [cert2, cert]
    expected_certs.sort()
    assert response == expected_certs

    # TODO : valid parameter seems to have no effect (to check with developers)
    # Test existing user with certificates, but only for valid certificates
    response = webadm_api_manager.get_user_certificates(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        False,
    )
    response.sort()
    expected_certs = [cert2, cert]
    expected_certs.sort()
    assert response == expected_certs


def test_get_user_settings() -> None:
    """
    Test Get_User_Settings method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_settings)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_settings(unknown_user_dn)
    exception_str = str(excinfo)
    assert (
        exception_str
        == f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\") tblen=3>"
    )

    # Test for all existing settings
    response = webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
    )
    assert isinstance(response, dict)
    list_keys = list(response.keys())
    list_keys.sort()
    assert list_keys == [
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
    ]

    # Test for non existing data
    response = webadm_api_manager.get_user_settings(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower(),
        [f"{RANDOM_STRING}.{RANDOM_STRING}"],
    )
    assert response == []

    # Test for 2 existing data
    response = webadm_api_manager.get_user_settings(
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


def test_get_user_ids() -> None:
    """
    Test Get_User_IDs method.
    """
    # Test issue with DN parameter
    _test_malformed_dns(webadm_api_manager.get_user_ids)

    # Test with unknown user
    unknown_user_dn = f"cn={RANDOM_STRING},{WEBADM_BASE_DN}".lower()
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.get_user_ids(unknown_user_dn)
    exception_str = str(excinfo)
    assert (
        exception_str
        == f"<ExceptionInfo InternalError(\"LDAP object '{unknown_user_dn}' does not exist\") tblen=3>"
    )

    # Test existing user
    response = webadm_api_manager.get_user_ids(
        f"CN=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}".lower()
    )
    assert isinstance(response, list)
    assert response == [f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1"]
