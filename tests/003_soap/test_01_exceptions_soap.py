import ssl

import aiohttp
import pytest

from pyrcdevs import OpenOTPSoap
from pyrcdevs.soap.SOAP import InvalidAPICredentials, InvalidParams, InvalidSOAPContent
from tests.common import get_full_exception_msg
from tests.constants import (
    RANDOM_STRING,
    WEBADM_HOST,
)


@pytest.mark.asyncio
async def test_wrong_host() -> None:
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorDNSError) as excinfo:
        await OpenOTPSoap("wrong_host", 8443, verify_mode=ssl.CERT_NONE).status()
    exception_msg = get_full_exception_msg(excinfo)
    assert "Name or service not known" in exception_msg


@pytest.mark.asyncio
async def test_wrong_ip() -> None:
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorError) as excinfo:
        await OpenOTPSoap(
            "127.56.18.94",
            8443,
            verify_mode=ssl.CERT_NONE,
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert "Connect call failed" in exception_msg


@pytest.mark.asyncio
async def test_wrong_port() -> None:
    # noinspection PyTypeChecker
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorError) as excinfo:
        await OpenOTPSoap(
            WEBADM_HOST,
            6666,
            verify_mode=ssl.CERT_NONE,
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert (
        "aiohttp.client_exceptions.ClientConnectorError: Cannot connect to host"
        in exception_msg
    )


@pytest.mark.asyncio
async def test_p12_api_key_together() -> None:
    with pytest.raises(InvalidParams) as excinfo:
        await OpenOTPSoap(
            WEBADM_HOST,
            8443,
            verify_mode=ssl.CERT_NONE,
            p12_file_path="/dev/null",
            p12_password="password",
            api_key="api_key",
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert "Client certificate and API key cannot be used together!" in exception_msg


@pytest.mark.asyncio
async def test_wrong_p12_file() -> None:
    with pytest.raises(ValueError) as excinfo:
        await OpenOTPSoap(
            WEBADM_HOST,
            8443,
            verify_mode=ssl.CERT_NONE,
            p12_file_path="/dev/null",
            p12_password=RANDOM_STRING,
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert "Could not deserialize PKCS12 data" in exception_msg


@pytest.mark.asyncio
async def test_wrong_p12_password() -> None:
    with pytest.raises(ValueError) as excinfo:
        await OpenOTPSoap(
            WEBADM_HOST,
            8443,
            verify_mode=ssl.CERT_NONE,
            p12_file_path="./clientsoap.p12",
            p12_password=RANDOM_STRING,
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert "Invalid password or PKCS12 data" in exception_msg


@pytest.mark.asyncio
async def test_wrong_api_key() -> None:
    with pytest.raises(InvalidAPICredentials) as excinfo:
        await OpenOTPSoap(
            WEBADM_HOST,
            8443,
            verify_mode=ssl.CERT_NONE,
            api_key=RANDOM_STRING,
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert "Invalid API key" in exception_msg


@pytest.mark.asyncio
async def test_wrong_soap_response() -> None:
    with pytest.raises(InvalidSOAPContent) as excinfo:
        await OpenOTPSoap(
            WEBADM_HOST,
            443,
            verify_mode=ssl.CERT_NONE,
            api_key="5860687476061196336_d788fd99ea4868f35c3b5e21ada3920b9501bb2c",
            timeout=2,
        ).status()

    exception_msg = get_full_exception_msg(excinfo)
    assert "404" in exception_msg
