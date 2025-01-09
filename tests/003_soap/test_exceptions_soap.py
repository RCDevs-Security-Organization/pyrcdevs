import re

import pytest
from requests.exceptions import ConnectionError, ConnectTimeout
from urllib3.exceptions import MaxRetryError, NewConnectionError

from pyrcdevs import OpenOTPSoap
from pyrcdevs.soap.SOAP import (InvalidAPICredentials, InvalidParams,
                                InvalidSOAPContent)
from tests.constants import (RANDOM_STRING, REGEX_CONNECT_TIMEOUT,
                             REGEX_CONNECTION_REFUSED, REGEX_FAILED_TO_RESOLVE,
                             REGEX_MAX_RETRY, WEBADM_HOST)


def test_wrong_host() -> None:
    with pytest.raises(ConnectionError) as excinfo:
        OpenOTPSoap("wrong_host", 8443, False).status()
    assert re.compile(REGEX_FAILED_TO_RESOLVE).search(str(excinfo.value))


def test_wrong_ip() -> None:
    with pytest.raises(ConnectionError) as excinfo:
        OpenOTPSoap(
            "127.56.18.94",
            8443,
            False,
            timeout=2,
        ).status()
    assert re.compile(REGEX_CONNECTION_REFUSED).search(str(excinfo.value))


def test_wrong_port() -> None:
    # noinspection PyTypeChecker
    with pytest.raises(
        (ConnectTimeout, NewConnectionError, MaxRetryError, OSError, ConnectionError)
    ) as excinfo:
        OpenOTPSoap(
            WEBADM_HOST,
            6666,
            False,
            timeout=2,
        ).status()
    assert (
        re.compile(REGEX_CONNECTION_REFUSED).search(str(excinfo.value))
        or re.compile(REGEX_CONNECT_TIMEOUT).search(str(excinfo.value))
        or re.compile(REGEX_MAX_RETRY).search(str(excinfo.value))
    )


def test_p12_api_key_together() -> None:
    with pytest.raises(InvalidParams) as excinfo:
        OpenOTPSoap(
            WEBADM_HOST,
            8443,
            False,
            p12_file_path="/dev/null",
            p12_password="password",
            api_key="api_key",
            timeout=2,
        ).status()
    assert (
        str(excinfo.value) == "Client certificate and API key cannot be used together!"
    )


def test_wrong_p12_file() -> None:
    with pytest.raises(ValueError) as excinfo:
        OpenOTPSoap(
            WEBADM_HOST,
            8443,
            False,
            p12_file_path="/dev/null",
            p12_password=RANDOM_STRING,
            timeout=2,
        ).status()
    assert str(excinfo.value) == "Could not deserialize PKCS12 data"


def test_wrong_p12_password() -> None:
    with pytest.raises(ValueError) as excinfo:
        OpenOTPSoap(
            WEBADM_HOST,
            8443,
            False,
            p12_file_path="./clientsoap.p12",
            p12_password=RANDOM_STRING,
            timeout=2,
        ).status()
    assert str(excinfo.value) == "Invalid password or PKCS12 data"


def test_wrong_api_key() -> None:
    with pytest.raises(InvalidAPICredentials) as excinfo:
        OpenOTPSoap(
            WEBADM_HOST,
            8443,
            False,
            api_key=RANDOM_STRING,
            timeout=2,
        ).status()
    assert str(excinfo.value) == "Invalid API key"


def test_wrong_soap_response() -> None:
    with pytest.raises(InvalidSOAPContent) as excinfo:
        OpenOTPSoap(
            WEBADM_HOST,
            443,
            False,
            api_key="5860687476061196336_d788fd99ea4868f35c3b5e21ada3920b9501bb2c",
            timeout=2,
        ).status()

    assert repr(excinfo.value) == (
        "InvalidSOAPContent('<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML "
        '2.0//EN">\\n<html><head>\\n<title>404 Not '
        "Found</title>\\n</head><body>\\n<h1>Not Found</h1>\\n<p>The requested URL was not "
        "found on this server.</p>\\n</body></html>\\n')"
    )
