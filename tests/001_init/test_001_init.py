import ldap
from ldap.ldapobject import SimpleLDAPObject

from tests.constants import LDAP_HOST, LDAP_BASE_DN, LDAP_USERNAME, LDAP_PASSWORD


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
        (
            "objectClass",
            ["organizationalUnit".encode("utf-8")],
        ),
        (
            "description",
            ["OU for pyrcdevs testing".encode("utf-8")],
        ),
    ]
    ldap_connection = ldap.initialize(f"ldap://{LDAP_HOST}:389")
    assert isinstance(ldap_connection, SimpleLDAPObject)
    ldap_connection.protocol_version = ldap.VERSION3
    ldap_connection.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
    try:
        ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_ONELEVEL)
        ldap_recursive_delete(ldap_connection, LDAP_BASE_DN, [LDAP_BASE_DN])
    except ldap.NO_SUCH_OBJECT:
        ldap_connection.add_s(LDAP_BASE_DN, attrs)
    assert ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_ONELEVEL) == []
    ldap_connection.unbind_s()
