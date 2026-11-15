"""Negative tests for the AC (access control) threats.

Each test builds a model that matches the threat, then flips the attribute(s)
under test and checks the threat no longer applies.
"""

import json
import os
from typing import Any

import pytest

from pytm import (
    TM,
    Actor,
    Data,
    Dataflow,
    Datastore,
    Lambda,
    Lifetime,
    Process,
    Server,
    Threat,
    TLSVersion,
)

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


@pytest.fixture(autouse=True)
def reset_tm() -> None:
    TM.reset()
    TM("ac negatives", description="negative tests")


def _set(target: Any, **controls: bool) -> None:
    """Set the given controls on the target."""
    for name, value in controls.items():
        setattr(target.controls, name, value)


def _credential_flow(
    life: Lifetime = Lifetime.LONG, is_credentials: bool = True
) -> Dataflow:
    user = Actor("User")
    web = Server("Web Server")
    flow = Dataflow(user, web, "User logs in")
    flow.data = Data("password", isCredentials=is_credentials, credentialsLife=life)
    return flow


class TestAC01:
    @pytest.mark.parametrize("cls", [Server, Process, Datastore])
    def test_AC01_does_not_apply_when_controls_present(self, cls) -> None:
        target = cls("target")
        threat = threats["AC01"]
        _set(target, hasAccessControl=False, authorizesSource=False)
        assert threat.apply(target)
        _set(target, hasAccessControl=True, authorizesSource=True)
        assert not threat.apply(target)

    def test_AC01_each_clause_alone_triggers(self) -> None:
        target = Server("web")
        threat = threats["AC01"]
        _set(target, hasAccessControl=True, authorizesSource=True)
        assert not threat.apply(target)
        _set(target, hasAccessControl=False)
        assert threat.apply(target)
        _set(target, hasAccessControl=True, authorizesSource=False)
        assert threat.apply(target)

    def test_AC01_does_not_apply_to_other_target_type(self) -> None:
        assert not threats["AC01"].apply(Actor("user"))


class TestAC02:
    def test_AC02_does_not_apply_to_unshared_datastore(self) -> None:
        db = Datastore("DB")
        db.isShared = True
        assert threats["AC02"].apply(db)
        db.isShared = False
        assert not threats["AC02"].apply(db)

    def test_AC02_does_not_apply_to_other_target_type(self) -> None:
        web = Server("web")
        web.isShared = True
        assert not threats["AC02"].apply(web)


class TestAC03:
    @pytest.mark.parametrize("cls", [Process, Lambda])
    def test_AC03_does_not_apply_without_environment_variables(self, cls) -> None:
        target = cls("target")
        threat = threats["AC03"]
        _set(
            target,
            implementsAuthenticationScheme=False,
            validatesInput=False,
            authorizesSource=False,
        )
        target.usesEnvironmentVariables = True
        assert threat.apply(target)
        target.usesEnvironmentVariables = False
        assert not threat.apply(target)

    @pytest.mark.parametrize(
        "control",
        ["implementsAuthenticationScheme", "validatesInput", "authorizesSource"],
    )
    def test_AC03_does_not_apply_when_all_controls_present(self, control) -> None:
        target = Process("proc")
        target.usesEnvironmentVariables = True
        threat = threats["AC03"]
        all_on = {
            "implementsAuthenticationScheme": True,
            "validatesInput": True,
            "authorizesSource": True,
        }
        _set(target, **all_on)
        assert not threat.apply(target)
        _set(target, **{control: False})
        assert threat.apply(target)

    def test_AC03_does_not_apply_to_other_target_type(self) -> None:
        target = Server("web")
        target.usesEnvironmentVariables = True
        assert not threats["AC03"].apply(target)


class TestAC04:
    def _flow(self, fmt: str) -> Dataflow:
        user = Actor("User")
        web = Server("Web Server")
        flow = Dataflow(user, web, "User sends data")
        flow.data = Data(name="payload", description="textual", format=fmt)
        return flow

    def test_AC04_does_not_apply_when_source_authorized(self) -> None:
        flow = self._flow("XML")
        threat = threats["AC04"]
        _set(flow, authorizesSource=False)
        assert threat.apply(flow)
        _set(flow, authorizesSource=True)
        assert not threat.apply(flow)

    def test_AC04_does_not_apply_to_non_xml_data(self) -> None:
        flow = self._flow("JSON")
        _set(flow, authorizesSource=False)
        assert not threats["AC04"].apply(flow)

    def test_AC04_does_not_apply_to_other_target_type(self) -> None:
        assert not threats["AC04"].apply(Server("web"))


class TestAC05:
    def _flow(self) -> Dataflow:
        process1 = Process("Process1")
        web = Server("Web Server")
        return Dataflow(process1, web, "Process calls a web API")

    def test_AC05_integrity_clause_needs_unencrypted_flow(self) -> None:
        flow = self._flow()
        threat = threats["AC05"]
        # silence the destination-authentication clause
        _set(flow, authenticatesDestination=True, checksDestinationRevocation=True)
        _set(flow.source, providesIntegrity=False)
        _set(flow.sink, providesIntegrity=True)
        _set(flow, isEncrypted=False)
        assert threat.apply(flow)
        _set(flow, isEncrypted=True)
        assert not threat.apply(flow)

    def test_AC05_integrity_clause_needs_missing_integrity(self) -> None:
        flow = self._flow()
        threat = threats["AC05"]
        _set(flow, authenticatesDestination=True, checksDestinationRevocation=True)
        _set(flow, isEncrypted=False)
        _set(flow.source, providesIntegrity=False)
        _set(flow.sink, providesIntegrity=False)
        assert threat.apply(flow)
        _set(flow.source, providesIntegrity=True)
        assert threat.apply(flow)  # sink still lacks integrity
        _set(flow.sink, providesIntegrity=True)
        assert not threat.apply(flow)

    def test_AC05_destination_clause_needs_authentication_and_revocation(
        self,
    ) -> None:
        flow = self._flow()
        threat = threats["AC05"]
        # silence the integrity clause
        _set(flow, isEncrypted=True)
        _set(flow.source, providesIntegrity=True)
        _set(flow.sink, providesIntegrity=True)
        _set(flow, authenticatesDestination=True, checksDestinationRevocation=True)
        assert not threat.apply(flow)
        _set(flow, authenticatesDestination=False)
        assert threat.apply(flow)
        _set(flow, authenticatesDestination=True, checksDestinationRevocation=False)
        assert threat.apply(flow)

    def test_AC05_destination_clause_ignores_responses(self) -> None:
        flow = self._flow()
        threat = threats["AC05"]
        _set(flow, isEncrypted=True)
        _set(flow.source, providesIntegrity=True)
        _set(flow.sink, providesIntegrity=True)
        _set(flow, authenticatesDestination=False)
        flow.isResponse = False
        assert threat.apply(flow)
        flow.isResponse = True
        assert not threat.apply(flow)

    def test_AC05_destination_clause_needs_in_scope_source(self) -> None:
        flow = self._flow()
        threat = threats["AC05"]
        _set(flow, isEncrypted=True)
        _set(flow.source, providesIntegrity=True)
        _set(flow.sink, providesIntegrity=True)
        _set(flow, authenticatesDestination=False)
        assert threat.apply(flow)
        flow.source.inScope = False
        assert not threat.apply(flow)

    def test_AC05_does_not_apply_to_other_target_type(self) -> None:
        assert not threats["AC05"].apply(Server("web"))


class TestAC06:
    def test_AC06_does_not_apply_to_hardened_server_with_access_control(
        self,
    ) -> None:
        web = Server("web")
        threat = threats["AC06"]
        _set(web, isHardened=False, hasAccessControl=False)
        assert threat.apply(web)
        _set(web, isHardened=True, hasAccessControl=True)
        assert not threat.apply(web)

    def test_AC06_each_clause_alone_triggers(self) -> None:
        web = Server("web")
        threat = threats["AC06"]
        _set(web, isHardened=True, hasAccessControl=True)
        _set(web, isHardened=False)
        assert threat.apply(web)
        _set(web, isHardened=True, hasAccessControl=False)
        assert threat.apply(web)

    def test_AC06_does_not_apply_to_other_target_type(self) -> None:
        proc = Process("proc")
        _set(proc, isHardened=False, hasAccessControl=False)
        assert not threats["AC06"].apply(proc)


@pytest.mark.parametrize("sid", ["AC07", "AC08"])
class TestAccessControlServer:
    def test_does_not_apply_with_access_control(self, sid) -> None:
        web = Server("web")
        _set(web, hasAccessControl=False)
        assert threats[sid].apply(web)
        _set(web, hasAccessControl=True)
        assert not threats[sid].apply(web)

    def test_does_not_apply_to_other_target_type(self, sid) -> None:
        proc = Process("proc")
        _set(proc, hasAccessControl=False)
        assert not threats[sid].apply(proc)


class TestAC09:
    def test_AC09_does_not_apply_with_both_controls(self) -> None:
        web = Server("web")
        threat = threats["AC09"]
        _set(web, hasAccessControl=False, authorizesSource=False)
        assert threat.apply(web)
        _set(web, hasAccessControl=True, authorizesSource=True)
        assert not threat.apply(web)

    def test_AC09_each_clause_alone_triggers(self) -> None:
        web = Server("web")
        threat = threats["AC09"]
        _set(web, hasAccessControl=True, authorizesSource=True)
        _set(web, hasAccessControl=False)
        assert threat.apply(web)
        _set(web, hasAccessControl=True, authorizesSource=False)
        assert threat.apply(web)

    def test_AC09_does_not_apply_to_other_target_type(self) -> None:
        proc = Process("proc")
        _set(proc, hasAccessControl=False)
        assert not threats["AC09"].apply(proc)


class TestAC10:
    def _server(self, flow_tls: TLSVersion) -> Server:
        user = Actor("User")
        web = Server("web")
        web.minTLSVersion = TLSVersion.TLSv11
        flow = Dataflow(user, web, "User connects")
        flow.protocol = "HTTPS"
        flow.tlsVersion = flow_tls
        web.inputs = [flow]
        return web

    def test_AC10_does_not_apply_when_tls_version_sufficient(self) -> None:
        web = self._server(TLSVersion.SSLv3)
        threat = threats["AC10"]
        _set(web, implementsAuthenticationScheme=False, authorizesSource=False)
        assert threat.apply(web)
        web.inputs[0].tlsVersion = TLSVersion.TLSv12
        assert not threat.apply(web)

    def test_AC10_does_not_apply_without_inputs(self) -> None:
        web = self._server(TLSVersion.SSLv3)
        threat = threats["AC10"]
        _set(web, implementsAuthenticationScheme=False, authorizesSource=False)
        assert threat.apply(web)
        web.inputs = []
        assert not threat.apply(web)

    def test_AC10_does_not_apply_with_authentication_and_authorization(
        self,
    ) -> None:
        web = self._server(TLSVersion.SSLv3)
        threat = threats["AC10"]
        _set(web, implementsAuthenticationScheme=True, authorizesSource=True)
        assert not threat.apply(web)
        _set(web, implementsAuthenticationScheme=False)
        assert threat.apply(web)
        _set(web, implementsAuthenticationScheme=True, authorizesSource=False)
        assert threat.apply(web)

    def test_AC10_does_not_apply_to_other_target_type(self) -> None:
        proc = Process("proc")
        assert not threats["AC10"].apply(proc)


class TestSessionIdentifiersServer:
    @pytest.mark.parametrize("sid", ["AC11", "AC16", "AC17"])
    def test_does_not_apply_with_strong_session_identifiers(self, sid) -> None:
        web = Server("web")
        _set(web, usesStrongSessionIdentifiers=False)
        assert threats[sid].apply(web)
        _set(web, usesStrongSessionIdentifiers=True)
        assert not threats[sid].apply(web)

    @pytest.mark.parametrize("sid", ["AC11", "AC16", "AC17"])
    def test_does_not_apply_to_other_target_type(self, sid) -> None:
        proc = Process("proc")
        _set(proc, usesStrongSessionIdentifiers=False)
        assert not threats[sid].apply(proc)


class TestAC12AC13:
    @pytest.mark.parametrize("sid", ["AC12", "AC13"])
    def test_does_not_apply_with_both_controls(self, sid) -> None:
        proc = Process("proc")
        threat = threats[sid]
        _set(proc, hasAccessControl=False, implementsPOLP=False)
        assert threat.apply(proc)
        _set(proc, hasAccessControl=True, implementsPOLP=True)
        assert not threat.apply(proc)

    @pytest.mark.parametrize("sid", ["AC12", "AC13"])
    def test_each_clause_alone_triggers(self, sid) -> None:
        proc = Process("proc")
        threat = threats[sid]
        _set(proc, hasAccessControl=True, implementsPOLP=True)
        _set(proc, hasAccessControl=False)
        assert threat.apply(proc)
        _set(proc, hasAccessControl=True, implementsPOLP=False)
        assert threat.apply(proc)

    @pytest.mark.parametrize("sid", ["AC12", "AC13"])
    def test_does_not_apply_to_other_target_type(self, sid) -> None:
        web = Server("web")
        _set(web, hasAccessControl=False, implementsPOLP=False)
        assert not threats[sid].apply(web)


class TestAC14:
    def test_AC14_does_not_apply_with_polp(self) -> None:
        proc = Process("proc")
        threat = threats["AC14"]
        _set(proc, implementsPOLP=False, validatesInput=False)
        assert threat.apply(proc)
        _set(proc, implementsPOLP=True)
        assert not threat.apply(proc)

    def test_AC14_does_not_apply_without_env_vars_and_with_validation(self) -> None:
        proc = Process("proc")
        threat = threats["AC14"]
        _set(proc, implementsPOLP=False, validatesInput=False)
        proc.usesEnvironmentVariables = False
        assert threat.apply(proc)
        _set(proc, validatesInput=True)
        assert not threat.apply(proc)

    def test_AC14_environment_variables_alone_trigger(self) -> None:
        proc = Process("proc")
        threat = threats["AC14"]
        _set(proc, implementsPOLP=False, validatesInput=True)
        proc.usesEnvironmentVariables = False
        assert not threat.apply(proc)
        proc.usesEnvironmentVariables = True
        assert threat.apply(proc)

    def test_AC14_does_not_apply_to_other_target_type(self) -> None:
        web = Server("web")
        _set(web, implementsPOLP=False, validatesInput=False)
        assert not threats["AC14"].apply(web)


class TestAC15:
    def test_AC15_does_not_apply_with_polp(self) -> None:
        proc = Process("proc")
        _set(proc, implementsPOLP=False)
        assert threats["AC15"].apply(proc)
        _set(proc, implementsPOLP=True)
        assert not threats["AC15"].apply(proc)

    def test_AC15_does_not_apply_to_other_target_type(self) -> None:
        web = Server("web")
        _set(web, implementsPOLP=False)
        assert not threats["AC15"].apply(web)


class TestAC18:
    def test_AC18_does_not_apply_with_connection_timeout(self) -> None:
        proc = Process("proc")
        threat = threats["AC18"]
        _set(
            proc,
            usesStrongSessionIdentifiers=False,
            encryptsCookies=False,
            definesConnectionTimeout=False,
        )
        assert threat.apply(proc)
        _set(proc, definesConnectionTimeout=True)
        assert not threat.apply(proc)

    def test_AC18_does_not_apply_with_strong_ids_and_encrypted_cookies(self) -> None:
        proc = Process("proc")
        threat = threats["AC18"]
        _set(proc, definesConnectionTimeout=False)
        _set(proc, usesStrongSessionIdentifiers=True, encryptsCookies=True)
        assert not threat.apply(proc)
        _set(proc, usesStrongSessionIdentifiers=False)
        assert threat.apply(proc)
        _set(proc, usesStrongSessionIdentifiers=True, encryptsCookies=False)
        assert threat.apply(proc)

    def test_AC18_does_not_apply_to_other_target_type(self) -> None:
        web = Server("web")
        assert not threats["AC18"].apply(web)


class TestAC19:
    def test_AC19_does_not_apply_with_nonce(self) -> None:
        web = Server("web")
        web.usesSessionTokens = True
        _set(web, implementsNonce=False)
        assert threats["AC19"].apply(web)
        _set(web, implementsNonce=True)
        assert not threats["AC19"].apply(web)

    def test_AC19_does_not_apply_without_session_tokens(self) -> None:
        web = Server("web")
        _set(web, implementsNonce=False)
        web.usesSessionTokens = True
        assert threats["AC19"].apply(web)
        web.usesSessionTokens = False
        assert not threats["AC19"].apply(web)

    def test_AC19_does_not_apply_to_other_target_type(self) -> None:
        proc = Process("proc")
        assert not threats["AC19"].apply(proc)


class TestAC20:
    def test_AC20_does_not_apply_with_connection_timeout(self) -> None:
        proc = Process("proc")
        threat = threats["AC20"]
        _set(
            proc,
            definesConnectionTimeout=False,
            usesMFA=False,
            encryptsSessionData=False,
        )
        assert threat.apply(proc)
        _set(proc, definesConnectionTimeout=True)
        assert not threat.apply(proc)

    def test_AC20_does_not_apply_with_mfa_and_encrypted_sessions(self) -> None:
        proc = Process("proc")
        threat = threats["AC20"]
        _set(proc, definesConnectionTimeout=False)
        _set(proc, usesMFA=True, encryptsSessionData=True)
        assert not threat.apply(proc)
        _set(proc, usesMFA=False)
        assert threat.apply(proc)
        _set(proc, usesMFA=True, encryptsSessionData=False)
        assert threat.apply(proc)

    def test_AC20_does_not_apply_to_other_target_type(self) -> None:
        assert not threats["AC20"].apply(Server("web"))


class TestAC21:
    def test_AC21_does_not_apply_with_csrf_token_and_session_verification(
        self,
    ) -> None:
        proc = Process("proc")
        threat = threats["AC21"]
        _set(proc, implementsCSRFToken=False, verifySessionIdentifiers=False)
        assert threat.apply(proc)
        _set(proc, implementsCSRFToken=True, verifySessionIdentifiers=True)
        assert not threat.apply(proc)

    def test_AC21_each_clause_alone_triggers(self) -> None:
        proc = Process("proc")
        threat = threats["AC21"]
        _set(proc, implementsCSRFToken=True, verifySessionIdentifiers=True)
        _set(proc, implementsCSRFToken=False)
        assert threat.apply(proc)
        _set(proc, implementsCSRFToken=True, verifySessionIdentifiers=False)
        assert threat.apply(proc)

    def test_AC21_does_not_apply_to_other_target_type(self) -> None:
        web = Server("web")
        _set(web, implementsCSRFToken=False, verifySessionIdentifiers=False)
        assert not threats["AC21"].apply(web)


@pytest.mark.parametrize(
    ("sid", "lives", "safe_lives"),
    [
        (
            "AC22",
            [Lifetime.UNKNOWN, Lifetime.LONG, Lifetime.MANUAL, Lifetime.HARDCODED],
            [Lifetime.NONE, Lifetime.SHORT, Lifetime.AUTO],
        ),
        (
            "AC23",
            [Lifetime.UNKNOWN, Lifetime.LONG, Lifetime.MANUAL],
            [Lifetime.NONE, Lifetime.SHORT, Lifetime.AUTO, Lifetime.HARDCODED],
        ),
        (
            "AC24",
            [Lifetime.HARDCODED],
            [
                Lifetime.NONE,
                Lifetime.UNKNOWN,
                Lifetime.SHORT,
                Lifetime.LONG,
                Lifetime.MANUAL,
                Lifetime.AUTO,
            ],
        ),
    ],
)
class TestCredentialLifetime:
    def test_applies_to_risky_lifetimes(self, sid, lives, safe_lives) -> None:
        for life in lives:
            assert threats[sid].apply(_credential_flow(life)), life

    def test_does_not_apply_to_other_lifetimes(self, sid, lives, safe_lives) -> None:
        for life in safe_lives:
            assert not threats[sid].apply(_credential_flow(life)), life

    def test_does_not_apply_without_credentials(self, sid, lives, safe_lives) -> None:
        assert threats[sid].apply(_credential_flow(lives[0]))
        flow = _credential_flow(lives[0], is_credentials=False)
        assert not threats[sid].apply(flow)

    def test_does_not_apply_when_sink_out_of_scope(self, sid, lives, safe_lives):
        flow = _credential_flow(lives[0])
        assert threats[sid].apply(flow)
        flow.sink.inScope = False
        assert not threats[sid].apply(flow)

    def test_does_not_apply_to_other_target_type(self, sid, lives, safe_lives):
        assert not threats[sid].apply(Server("web"))
