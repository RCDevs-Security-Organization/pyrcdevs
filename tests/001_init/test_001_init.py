from datetime import datetime, timedelta

import ldap
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, CertificateSigningRequest
from ldap.ldapobject import SimpleLDAPObject

from tests.constants import (CA_CERT_PATH, CA_KEY_PATH, CLUSTER_TYPE,
                             LDAP_BASE_DN, LDAP_HOST, LDAP_PASSWORD,
                             LDAP_USERNAME, TESTER_NAME, USER_CERT_PATH)


def test_init() -> None:
    set_ldap()
    generate_user_certificates()


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


def generate_user_certificates():
    """
    This method generates and saves to disk a certificate
    :return:
    """
    key = generate_rsa_private_key()
    csr = generate_csr(key)
    cert = issue_cert(csr)
    save_certificate(cert)
    cert2 = issue_cert(csr, 1)
    save_certificate(cert2, f"{USER_CERT_PATH}_2")


def save_certificate(cert, path: str = USER_CERT_PATH) -> None:
    """
    This method saves certificate as PEM to path defined by USER_CERT_PATH variable
    :param Certificate cert: certiticate
    :param str path: path where to save certiticate
    """
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def issue_cert(csr: CertificateSigningRequest, validity: int = 31536000) -> Certificate:
    """
    This method issue a certificate based on given CSR, using CA provided by CA_CERT_PATH and CA_KEY_PATH variables
    :param CertificateSigningRequest csr: CSR
    :param int validity: how many seconds the certificate is valid (Default to one year)
    :return: issued certificate
    :rtype: Certificate
    """
    with open(CA_CERT_PATH, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read())
    with open(CA_KEY_PATH, "rb") as ca_key_file:
        ca_key = serialization.load_pem_private_key(ca_key_file.read(), password=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    x509.ExtendedKeyUsageOID.EMAIL_PROTECTION,
                    x509.ExtendedKeyUsageOID.SMARTCARD_LOGON,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.34617.3.1.1"), b"USER"
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .not_valid_before(datetime.now() - timedelta(days=1))
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.now()
            + timedelta(seconds=validity)
            # Sign our certificate with our private key
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert


def generate_csr(key: RSAPrivateKey) -> CertificateSigningRequest:
    """
    This method generates and returns a CSR
    :param RSAPrivateKey key: private RSA key
    :return: CSR
    :rtype: CertificateSigningRequest
    """
    username = f"u_{TESTER_NAME[:3]}_{CLUSTER_TYPE[:1]}_api_1"
    domain = "Domain_Enabled"
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    # Provide various details about who we are.
                    x509.NameAttribute(NameOID.USER_ID, username),
                    x509.NameAttribute(NameOID.SURNAME, username),
                    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, domain),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_IDENTIFIER, "VATLU-00000000"
                    ),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RCDevs Support"),
                    x509.NameAttribute(
                        NameOID.COMMON_NAME,
                        f"{domain}\\{username}",
                    ),
                ]
            )
        )
        .sign(key, hashes.SHA256())
    )
    return csr


def generate_rsa_private_key(
    public_exponent: int = 65537, key_size: int = 4096
) -> RSAPrivateKey:
    """
    This method generates and returns a private RSA key

    :param int public_exponent:
    :param int key_size:
    :return: private RSA key
    :rtype: RSAPrivateKey
    """
    key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    return key


def set_ldap() -> None:
    """
    This method creates specific pyrcdevs OU at the root of testing OU
    """
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
        status = ldap_recursive_delete(ldap_connection, LDAP_BASE_DN, [LDAP_BASE_DN])
        assert status
    except ldap.NO_SUCH_OBJECT:
        ldap_connection.add_s(LDAP_BASE_DN, attrs)
    assert ldap_connection.search_s(LDAP_BASE_DN, ldap.SCOPE_ONELEVEL) == []
    ldap_connection.unbind_s()
