import re

import pytest
from requests.exceptions import ConnectionError, ConnectTimeout
from urllib3.exceptions import MaxRetryError, NewConnectionError

from pyrcdevs import WebADMManager
from tests.constants import REGEX_FAILED_TO_RESOLVE, REGEX_CONNECTION_REFUSED, REGEX_CONNECT_TIMEOUT, REGEX_MAX_RETRY, \
    WEBADM_API_USERNAME, WEBADM_API_PASSWORD, WEBADM_HOST


def test_wrong_host() -> None:
    with pytest.raises(ConnectionError) as excinfo:
        WebADMManager(
            "wrong_host", "443", WEBADM_API_USERNAME, WEBADM_API_PASSWORD, False
        )
    assert re.compile(REGEX_FAILED_TO_RESOLVE).search(str(excinfo.value))


def test_wrong_ip() -> None:
    with pytest.raises(ConnectionError) as excinfo:
        WebADMManager(
            "127.56.18.94",
            "443",
            WEBADM_API_USERNAME,
            WEBADM_API_PASSWORD,
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
            WEBADM_HOST,
            "6666",
            WEBADM_API_USERNAME,
            WEBADM_API_PASSWORD,
            False,
            timeout=2,
        )
    print(str(excinfo))
    assert (
        re.compile(REGEX_CONNECTION_REFUSED).search(str(excinfo.value))
        or re.compile(REGEX_CONNECT_TIMEOUT).search(str(excinfo.value))
        or re.compile(REGEX_MAX_RETRY).search(str(excinfo.value))
    )
