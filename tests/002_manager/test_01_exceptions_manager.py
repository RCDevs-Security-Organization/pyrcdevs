import ssl

import aiohttp
import pytest

from pyrcdevs import WebADMManager
from pyrcdevs.manager.Manager import InvalidAPICredentials
from tests.constants import WEBADM_API_PASSWORD, WEBADM_API_USERNAME, WEBADM_HOST


@pytest.mark.asyncio
async def test_wrong_host() -> None:
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorDNSError) as excinfo:
        await WebADMManager(
            "wrong_host",
            WEBADM_API_USERNAME,
            WEBADM_API_PASSWORD,
            443,
            verify_mode=ssl.CERT_NONE,
        ).server_status()
    assert "Name or service not known" in str(excinfo)


@pytest.mark.asyncio
async def test_wrong_ip() -> None:
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorError) as excinfo:
        await WebADMManager(
            "127.56.18.94",
            WEBADM_API_USERNAME,
            WEBADM_API_PASSWORD,
            443,
            verify_mode=ssl.CERT_NONE,
            timeout=2,
        ).server_status()
    assert 'ConnectionRefusedError(111, "Connect call failed' in str(excinfo)


@pytest.mark.asyncio
async def test_wrong_port() -> None:
    # noinspection PyTypeChecker
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorError) as excinfo:
        await WebADMManager(
            WEBADM_HOST,
            WEBADM_API_USERNAME,
            WEBADM_API_PASSWORD,
            6666,
            verify_mode=ssl.CERT_NONE,
            timeout=2,
        ).server_status()

    assert 'ConnectionRefusedError(111, "Connect call failed' in str(excinfo)


@pytest.mark.asyncio
async def test_wrong_api_credentials() -> None:
    # noinspection PyTypeChecker
    with pytest.raises(InvalidAPICredentials) as excinfo:
        await WebADMManager(
            WEBADM_HOST,
            "wrong_username",
            "wrong_password",
            443,
            verify_mode=ssl.CERT_NONE,
            timeout=2,
        ).server_status()
    assert str(excinfo).startswith("<ExceptionInfo InvalidAPICredentials(")
