"""This module implements tests for WebADM API Manager."""

import re

import pytest

import pyrcdevs
from pyrcdevs import WebADMManager
from pyrcdevs.constants import MSG_NOT_RIGHT_TYPE
from pyrcdevs.manager import InternalError
from pyrcdevs.manager.Manager import InvalidParams
from pyrcdevs.manager.WebADMManager import (AutoConfirmApplication,
                                            AutoConfirmExpiration,
                                            ConfigObjectApplication,
                                            ConfigObjectType,
                                            EventLogApplication,
                                            LicenseProduct)
from tests.constants import (CLUSTER_TYPE, DEFAULT_PASSWORD, GROUP_OBJECTCLASS,
                             LDAP_BASE_DN, LIST_STATUS_SERVERS_KEYS,
                             LIST_STATUS_WEB_TYPES, OPENOTP_PUSHID,
                             OPENOTP_TOKENKEY, RANDOM_STRING,
                             REGEX_LOGTIME_TIME, REGEX_PARAMETER_DN_NOT_STRING,
                             REGEX_VERSION_NUMBER, TESTER_NAME, USER_CERT_PATH,
                             WEBADM_API_PASSWORD, WEBADM_API_USERNAME,
                             WEBADM_BASE_DN, WEBADM_HOST)

webadm_api_manager = WebADMManager(
    WEBADM_HOST, "443", WEBADM_API_USERNAME, WEBADM_API_PASSWORD, False
)


def generate_user_attrs(
    username: str, uid_number: int = None, gid_number: int = None
) -> dict:
    """
    This method creates and returns a dictionary of user attributes
    :param str username: username of account
    :param int uid_number: UID number of account for posixaccount objectclass
    :param int gid_number: GID number of account for posixaccount objectclass
    :return: a dictionary of user attributes
    :rtype: dict
    """
    user_attributes = {
        "objectclass": ["person", "inetorgperson"],
        "sn": username,
        "cn": username,
        "uid": username,
    }
    if None not in (uid_number, gid_number):
        # noinspection PyUnresolvedReferences
        user_attributes["objectclass"].append("posixAccount")
        user_attributes["uidnumber"] = uid_number
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
            f"cn=testfail,ou={RANDOM_STRING},{WEBADM_BASE_DN}",
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
        == f"<ExceptionInfo InternalError(\"Could not create LDAP object 'cn=testfail,ou={RANDOM_STRING},"
        f"{WEBADM_BASE_DN}' (No such object)\") tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not create LDAP object 'cn=testfail,ou={RANDOM_STRING},"
        f"{WEBADM_BASE_DN[:47]}..., data 0, best match of:\\t'{LDAP_BASE_DN}')\") tblen=3>"
        or str(excinfo.value)
        == f"Could not create LDAP object 'cn=testfail,ou={RANDOM_STRING},{WEBADM_BASE_DN}' "
        f"(0000208D: NameErr: DSID-0310028D, problem 2001 (NO_OBJECT), data 0, best match "
        f"of:\t'{LDAP_BASE_DN}')"
    )

    # Test creating testfail object with no attribute information
    response = webadm_api_manager.create_ldap_object(
        f"cn=testfail,{WEBADM_BASE_DN}",
        {},
    )
    assert not response

    # Test creating testuserapi1 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1", 500, 100
    )
    response = webadm_api_manager.create_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi2 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2", 501, 100
    )
    response = webadm_api_manager.create_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_2,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi3 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3"
    )
    response = webadm_api_manager.create_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testuserapi4 object
    user_attributes = generate_user_attrs(
        f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4"
    )
    response = webadm_api_manager.create_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating again testuserapi1 object
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        user_attributes = generate_user_attrs(f"u_{CLUSTER_TYPE}_api_1", 500, 100)
        webadm_api_manager.create_ldap_object(
            f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
            user_attributes,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,"
        f"{WEBADM_BASE_DN}' already exist\") tblen=3>"
    )

    # Test creating unactivated object
    user_attributes = generate_user_attrs(f"u_{CLUSTER_TYPE}_unact")
    response = webadm_api_manager.create_ldap_object(
        f"cn=u_{CLUSTER_TYPE}_unact,{WEBADM_BASE_DN}",
        user_attributes,
    )
    assert response

    # Test creating testgroup1 object
    group_attributes = generate_group_attrs(f"g_{CLUSTER_TYPE}_api_1", 100)
    response = webadm_api_manager.create_ldap_object(
        f"cn=g_{CLUSTER_TYPE}_api_1,{WEBADM_BASE_DN}",
        group_attributes,
    )
    assert response

    # Test creating testgroup2 object
    group_attributes = generate_group_attrs(f"g_{CLUSTER_TYPE}_api_2", 101)
    response = webadm_api_manager.create_ldap_object(
        f"cn=g_{CLUSTER_TYPE}_api_2,{WEBADM_BASE_DN}",
        group_attributes,
    )
    assert response


def test_activate_ldap_object() -> None:
    """
    Test Activate_LDAP_Object method.
    """
    # Test to activate non existing object

    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.activate_ldap_object(
            f"cn=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}"
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=Not_exist_{RANDOM_STRING},o=root' does not exist\") "
        f"tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}' "
        'does not exist") tblen=3>'
    )

    # Test to activate providing a malformed DN
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.activate_ldap_object(RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
        f"NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of:"
        f"\\t'{RANDOM_STRING}')\") tblen=3>"
    )

    # Test to activate existing account
    response = webadm_api_manager.activate_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account
    response = webadm_api_manager.activate_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account
    response = webadm_api_manager.activate_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing account already activated
    response = webadm_api_manager.activate_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
    )
    assert not response

    # Test to activate existing group
    response = webadm_api_manager.activate_ldap_object(
        f"cn=g_{CLUSTER_TYPE}_api_1,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing group
    response = webadm_api_manager.activate_ldap_object(
        f"cn=g_{CLUSTER_TYPE}_api_2,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    # Test to activate existing group already activated
    response = webadm_api_manager.activate_ldap_object(
        f"cn=g_{CLUSTER_TYPE}_api_1,{WEBADM_BASE_DN}"
    )
    assert not response


def test_deactivate_ldap_object() -> None:
    """
    Test Deactivate_LDAP_Object method.
    """
    # Test to deactivate non existing object

    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.deactivate_ldap_object(
            f"cn=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}"
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=Not_exist_{RANDOM_STRING},o=root' does not exist\") "
        f"tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn=Not_exist_{RANDOM_STRING},{WEBADM_BASE_DN}' "
        f'does not exist") tblen=3>'
    )

    # Test to deactivate providing a malformed DN
    with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
        webadm_api_manager.deactivate_ldap_object(RANDOM_STRING)
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (invalid DN)\") tblen=3>"
        or str(excinfo)
        == f"<ExceptionInfo InternalError(\"Could not read LDAP object '{RANDOM_STRING}' (0000208F: "
        "NameErr: DSID-03100233, problem 2006 (BAD_NAME), data 8350, best match of"
        f":\\t'{RANDOM_STRING}')\") tblen=3>"
    )

    # Test to deactivate an activated account
    response = webadm_api_manager.deactivate_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
    )
    if "metadata" in WEBADM_HOST:
        assert not response
    else:
        assert response

    if "metadata" not in WEBADM_HOST:
        with pytest.raises(pyrcdevs.manager.Manager.InternalError) as excinfo:
            webadm_api_manager.deactivate_ldap_object(
                f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,{WEBADM_BASE_DN}"
            )
        assert (
            str(excinfo)
            == f"<ExceptionInfo InternalError(\"Object 'cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_3,"
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
        f"cn={RANDOM_STRING},{WEBADM_BASE_DN}"
    )
    assert not check_ldap_object_response

    # Test with existing DN object
    check_ldap_object_response = webadm_api_manager.check_ldap_object(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
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
            webadm_api_manager.check_user_active(f"cn={RANDOM_STRING},{WEBADM_BASE_DN}")
        assert (
            str(excinfo)
            == f"<ExceptionInfo InternalError(\"Could not read LDAP object 'cn={RANDOM_STRING},{WEBADM_BASE_DN}' "
            f'(No such object)") tblen=3>'
            or str(excinfo)
            == f"<ExceptionInfo InternalError(\"Could not read LDAP object 'cn={RANDOM_STRING},"
            f"{WEBADM_BASE_DN[:61]}..., data 0, best match of:\\t'{WEBADM_BASE_DN}')\") tblen=3>"
        )

        # Test with existing activated user object (testuserapi1)
        response = webadm_api_manager.check_user_active(
            f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}"
        )
        assert response

        # Test with existing unactivated user object (unactivated)
        response = webadm_api_manager.check_user_active(
            f"cn=u_{CLUSTER_TYPE}_unact,{WEBADM_BASE_DN}"
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
            f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}", 1
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
            f"cn={RANDOM_STRING},{WEBADM_BASE_DN}",
            DEFAULT_PASSWORD,
        )
    assert (
        str(excinfo)
        == f"<ExceptionInfo InternalError(\"LDAP object 'cn={RANDOM_STRING},{WEBADM_BASE_DN}' "
        f'does not exist") tblen=3>'
    )

    # Test with existing DN object, but a wrong password
    check_user_password_response = webadm_api_manager.check_user_password(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
        "wrong password",
    )
    assert not check_user_password_response

    # Test with existing DN object, and the right password
    check_user_password_response = webadm_api_manager.check_user_password(
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
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
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
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
        f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1,{WEBADM_BASE_DN}",
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
        EventLogApplication.OPENOTP, max_=1, dn=f"cn={RANDOM_STRING},{WEBADM_BASE_DN}"
    )
    assert response == []

    # Test to get event logs for an existing DN without any authentication
    response = webadm_api_manager.get_event_logs(
        EventLogApplication.OPENOTP,
        max_=1,
        dn=f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_4,{WEBADM_BASE_DN}",
    )
    assert response == []

    # Test to get only one event log for an existing DN with authentications
    if CLUSTER_TYPE == "mssp":
        user_w_auth = (
            f"cn=u_cp_allowed,{WEBADM_BASE_DN.lower().replace('ou=pyrcdevs,', '')}"
        )
    else:
        user_w_auth = (
            f"cn=u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_cp_allowed,{WEBADM_BASE_DN.lower().replace('ou=pyrcdevs,', '')}"
        )

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
