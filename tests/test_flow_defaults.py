"""Flow defaults fill in what a model left unset, and keep what it set."""

import json
import os
import random

import pytest

from pytm import (
    TM,
    Actor,
    Classification,
    Data,
    Dataflow,
    Server,
    Threat,
    TLSVersion,
)
from pytm.base import set_default
from pytm.pytm import _apply_defaults


@pytest.fixture(autouse=True)
def reset_tm():
    random.seed(0)
    TM.reset()
    yield
    TM.reset()


def _process():
    _apply_defaults(TM._flows, TM._data)


def _servers():
    client = Actor("Client")
    # Sink defaults that differ from what the flows set.
    idp = Server("IdP", protocol="LDAP", port=389)
    return client, idp


class TestForwardFlows:
    def test_explicit_values_are_kept(self):
        TM("forward tm")
        client, idp = _servers()
        flow = Dataflow(client, idp, "login", protocol="HTTPS", dstPort=443)
        flow.controls.isEncrypted = True
        flow.controls.authenticatesDestination = True
        flow.controls.checksDestinationRevocation = True

        _process()

        assert (flow.protocol, flow.dstPort) == ("HTTPS", 443)
        assert flow.controls.isEncrypted is True
        assert flow.controls.authenticatesDestination is True
        assert flow.controls.checksDestinationRevocation is True

    def test_explicit_values_that_match_the_type_default_are_kept(self):
        TM("forward tm")
        client, idp = _servers()
        idp.controls.isEncrypted = True
        flow = Dataflow(client, idp, "login")
        flow.controls.isEncrypted = False  # deliberately not encrypted

        _process()

        assert flow.controls.isEncrypted is False

    def test_unset_values_come_from_the_sink_and_source(self):
        TM("forward tm")
        client, idp = _servers()
        idp.controls.isEncrypted = True
        client.controls.authenticatesDestination = True
        flow = Dataflow(client, idp, "login")

        _process()

        assert (flow.protocol, flow.dstPort) == ("LDAP", 389)
        assert flow.controls.isEncrypted is True
        assert flow.controls.authenticatesDestination is True


class TestResponseFlows:
    def test_explicit_values_are_kept(self):
        TM("response tm")
        client, idp = _servers()
        request = Dataflow(client, idp, "login")
        response = Dataflow(
            idp, client, "assertion", responseTo=request, protocol="HTTPS", srcPort=443
        )
        response.controls.isEncrypted = True

        _process()

        assert (response.protocol, response.srcPort) == ("HTTPS", 443)
        assert response.controls.isEncrypted is True

    def test_unset_values_come_from_the_source(self):
        TM("response tm")
        client, idp = _servers()
        idp.controls.isEncrypted = True
        request = Dataflow(client, idp, "login")
        response = Dataflow(idp, client, "assertion", responseTo=request)

        _process()

        assert (response.protocol, response.srcPort) == ("LDAP", 389)
        assert response.controls.isEncrypted is True


class TestData:
    def _flow(self, datum):
        TM("data tm")
        app = Server("App")
        app.controls.isEncryptedAtRest = True
        return Dataflow(Actor("Client"), app, "store", data=datum)

    def test_explicit_encryption_at_rest_is_kept(self):
        token = Data("Token", isStored=True, isDestEncryptedAtRest=False)
        self._flow(token)

        _process()

        assert token.isDestEncryptedAtRest is False

    def test_unset_encryption_at_rest_comes_from_the_sink(self):
        token = Data("Token", isStored=True)
        self._flow(token)

        _process()

        assert token.isDestEncryptedAtRest is True

    def test_the_first_flow_fills_in_a_value(self):
        TM("data tm")
        token = Data("Token", isStored=True)
        encrypted = Server("Encrypted")
        encrypted.controls.isEncryptedAtRest = True
        Dataflow(Actor("Client"), encrypted, "first", data=token)
        Dataflow(Actor("Other"), Server("Plain"), "second", data=token)

        _process()

        # Filled in once, like the write-once attributes before pydantic.
        assert token.isDestEncryptedAtRest is True


class TestLevels:
    def test_unset_levels_come_from_both_ends(self):
        TM("levels tm")
        a = Actor("A", levels=[1, 2])
        b = Server("B", levels=[2, 3])
        flow = Dataflow(a, b, "x")

        _process()

        assert flow.levels == {2}

    def test_explicit_levels_are_kept(self):
        TM("levels tm")
        a = Actor("A", levels=[1, 2])
        b = Server("B", levels=[2, 3])
        flow = Dataflow(a, b, "x", levels=[1])

        _process()

        assert flow.levels == {1}


def test_set_default_fills_only_unset_valid_values():
    flow = Dataflow(Actor("A"), Server("B"), "x", protocol="HTTPS")

    set_default(flow, "protocol", "HTTP")
    set_default(flow, "dstPort", 8080)
    set_default(flow, "srcPort", 22)  # filled in now counts as set
    set_default(flow, "srcPort", 23)
    set_default(flow.controls, "isEncrypted", object())  # invalid: ignored

    assert (flow.protocol, flow.dstPort, flow.srcPort) == ("HTTPS", 8080, 22)
    assert flow.controls.isEncrypted is False


def test_encrypted_flow_does_not_get_transport_findings():
    tm = TM("threat tm")
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(dir_path, "..", "pytm", "threatlib", "threats.json")) as f:
        library = {t["SID"]: t for t in json.load(f)}
    TM._threats[:] = [Threat(**library[sid]) for sid in ("DE01", "CR08")]
    client = Actor("Client")
    client.controls.authenticatesDestination = False  # explicit on the flow below
    idp = Server("IdP")  # isEncrypted False, protocol "" by default
    flow = Dataflow(
        client,
        idp,
        "login",
        protocol="HTTPS",
        dstPort=443,
        tlsVersion=TLSVersion.TLSv12,
    )
    flow.controls.isEncrypted = True
    flow.controls.authenticatesDestination = True
    flow.controls.checksDestinationRevocation = True
    Data("Token", classification=Classification.SECRET)

    _process()
    tm.resolve()

    assert [f.threat_id for f in tm.findings] == []
