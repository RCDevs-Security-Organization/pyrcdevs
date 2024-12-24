import os
import re

import pytest
from requests.exceptions import ConnectionError, ConnectTimeout
from urllib3.exceptions import MaxRetryError, NewConnectionError

from pyrcdevs import WebADMManager

REGEX_FAILED_TO_RESOLVE = (
    r"HTTPSConnectionPool\(host='wrong_host', port=443\): Max retries exceeded with url: /manag/"
    r" \(Caused by NameResolutionError\(\"<urllib3.connection.HTTPSConnection object at "
    r"0x[0-9a-f]{12}>: Failed to resolve 'wrong_host' "
    r"\(\[Errno -2\] Name or service not known\)\"\)\)"
)

REGEX_CONNECTION_REFUSED = (
    r"HTTPSConnectionPool\(host='[0-9.]+', port=[0-9]+\): Max retries exceeded with url: "
    r"/manag/ \(Caused by NewConnectionError\('<urllib3.connection.HTTPSConnection object at "
    r"0x[0-9a-f]{12}>: Failed to establish a new connection: \[Errno 111\] Connection "
    r"refused'\)\)"
)

REGEX_CONNECT_TIMEOUT = (
    r"HTTPSConnectionPool\(host='[^']*', port=[0-9]+\): Max retries exceeded with url: /manag/ \("
    r"Caused by (ConnectTimeoutError)\(<urllib3.connection.HTTPSConnection object at 0x[0-9a-f]{"
    r"12}>, 'Connection to [^ ]* timed out. \(connect timeout=[0-9]+\)'\)\)"
)

REGEX_MAX_RETRY = (
    r"HTTPSConnectionPool\(host='[^']*', port=[0-9]+\): Max retries exceeded with url: /manag/ \("
    r"Caused by NewConnectionError\('<urllib3.connection.HTTPSConnection object at 0x[0-9a-f]{"
    r"12}>: Failed to establish a new connection: \[Errno 113\] No route to host'\)\)"
)

webadm_host = os.environ["WEBADM_HOST"]
webadm_api_username = os.environ["WEBADM_API_USERNAME"]
webadm_api_password = os.environ["WEBADM_API_PASSWORD"]


def test_wrong_host() -> None:
    with pytest.raises(ConnectionError) as excinfo:
        WebADMManager(
            "wrong_host", "443", webadm_api_password, webadm_api_password, False
        )
    assert re.compile(REGEX_FAILED_TO_RESOLVE).search(str(excinfo.value))


def test_wrong_ip() -> None:
    with pytest.raises(ConnectionError) as excinfo:
        WebADMManager(
            "127.56.18.94",
            "443",
            webadm_api_password,
            webadm_api_password,
            False,
            timeout=2,
        )
    assert re.compile(REGEX_CONNECTION_REFUSED).search(str(excinfo.value))


def test_wrong_port() -> None:
    # noinspection PyTypeChecker
    with pytest.raises(
        (ConnectTimeout, NewConnectionError, MaxRetryError, OSError, ConnectionError)
    ) as excinfo:
        WebADMManager(
            webadm_host,
            "6666",
            webadm_api_username,
            webadm_api_password,
            False,
            timeout=2,
        )
    print(str(excinfo))
    assert (
        re.compile(REGEX_CONNECTION_REFUSED).search(str(excinfo.value))
        or re.compile(REGEX_CONNECT_TIMEOUT).search(str(excinfo.value))
        or re.compile(REGEX_MAX_RETRY).search(str(excinfo.value))
    )
