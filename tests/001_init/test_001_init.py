import os

import ldap
from ldap.ldapobject import SimpleLDAPObject

DN_PYRCDEVS_BASE_DN = "ou=pyrcdevs,o=root"

webadm_host = os.environ["WEBADM_HOST"]
webadm_admin_dn = os.environ["WEBADM_ADMIN_DN"]
webadm_admin_password = os.environ["WEBADM_ADMIN_PASSWORD"]


def ldap_recursive_delete(conn, base_dn, excluded_dns):
    search = conn.search_s(base_dn, ldap.SCOPE_ONELEVEL)

    return_status = True

    for dn, _ in search:
        return_status = ldap_recursive_delete(conn, dn, excluded_dns)

    if base_dn not in excluded_dns:
        try:
            conn.delete_s(base_dn)
        except (ldap.NO_SUCH_OBJECT, ldap.INSUFFICIENT_ACCESS):
            return_status = False
    return return_status


def test_init() -> None:
    attrs = [
        ('objectClass', ['organizationalUnit'.encode('utf-8')]),  # Define the object class
        ('description', ['OU for pyrcdevs testing'.encode('utf-8')]),  # Optional description attribute
    ]
    ldap_connection = ldap.initialize(f"ldap://{webadm_host}:389")
    assert isinstance(ldap_connection, SimpleLDAPObject)
    ldap_connection.protocol_version = ldap.VERSION3
    ldap_connection.simple_bind_s(webadm_admin_dn, webadm_admin_password)
    try:
        ldap_connection.search_s(DN_PYRCDEVS_BASE_DN, ldap.SCOPE_ONELEVEL)
        ldap_recursive_delete(ldap_connection, DN_PYRCDEVS_BASE_DN, [DN_PYRCDEVS_BASE_DN])
    except ldap.NO_SUCH_OBJECT:
        ldap_connection.add_s(DN_PYRCDEVS_BASE_DN, attrs)
    assert ldap_connection.search_s(DN_PYRCDEVS_BASE_DN, ldap.SCOPE_ONELEVEL) == []
    ldap_connection.unbind_s()
