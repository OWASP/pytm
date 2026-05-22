import pytest

from pytm import Process, Server, TM
from pytm.dataflow import Dataflow
from pytm.flows import reply, req_reply


@pytest.fixture(autouse=True)
def reset_tm():
    TM.reset()
    yield
    TM.reset()


def test_req_reply_creates_bidirectional_flows():
    client = Process("Client")
    api = Server("API")

    request, response = req_reply(client, api, "Fetch data")

    assert request.source is client
    assert request.sink is api
    assert response.source is api
    assert response.sink is client
    assert response.responseTo is request
    assert request.response is response
    assert response.isResponse is True
    assert request.isResponse is False


def test_req_reply_uses_custom_reply_name():
    client = Process("Client")
    api = Server("API")

    _, response = req_reply(client, api, "Fetch data", reply_name="Custom Reply")

    assert response.name == "Custom Reply"


def test_reply_creates_response_with_default_name():
    client = Process("Client")
    api = Server("API")
    request = Dataflow(client, api, "Sync")

    original, response = reply(request)

    assert original is request
    assert response.name == "Reply to Sync"
    assert response.source is api
    assert response.sink is client
    assert response.responseTo is request
    assert request.response is response
    assert response.isResponse is True
    assert request.isResponse is False


def test_reply_applies_custom_kwargs():
    client = Process("Client")
    api = Server("API")
    request = Dataflow(client, api, "Sync")

    _, response = reply(
        request,
        name="Sync Response",
        protocol="HTTPS",
        note="Cached",
    )

    assert response.name == "Sync Response"
    assert response.protocol == "HTTPS"
    assert response.note == "Cached"
    assert response.responseTo is request
    assert request.response is response
