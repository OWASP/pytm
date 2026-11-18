"""Negative tests: each threat condition must be able to evaluate to false.

Every test first builds a model the threat applies to, then changes exactly the
attribute under test and asserts the threat no longer applies.
"""

import json
import os
from collections.abc import Callable

import pytest

from pytm import (
    TM,
    Actor,
    Classification,
    Data,
    Dataflow,
    Datastore,
    ExternalEntity,
    Lambda,
    Process,
    Server,
    Threat,
    TLSVersion,
)
from pytm.element import Element

with open(
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    + "/pytm/threatlib/threats.json",
) as threat_file:
    threats = {t["SID"]: Threat(**t) for t in json.load(threat_file)}


@pytest.fixture(autouse=True)
def reset_tm() -> None:
    TM.reset()
    TM("negatives tm", description="negative threat tests")


KINDS: dict[str, Callable[[], Element]] = {
    "Server": lambda: Server("Server"),
    "Process": lambda: Process("Process"),
    "Lambda": lambda: Lambda("Lambda"),
    "Datastore": lambda: Datastore("Datastore"),
}


def set_controls(target: Element, names: list[str], value: bool) -> None:
    for name in names:
        setattr(target.controls, name, value)


def make_flow() -> Dataflow:
    return Dataflow(Actor("User"), Server("Web"), "flow")


# ---------------------------------------------------------------------------
# Threats whose condition is an "or" of "<control> is False" clauses
# (SID, target kinds, controls that must all hold to mitigate the threat)
# ---------------------------------------------------------------------------
OR_RULES = [
    ("DE02", ["Server", "Process"], ["validatesInput", "sanitizesInput"]),
    ("DO01", ["Server", "Process"], ["handlesResourceConsumption", "isResilient"]),
    (
        "DO02",
        ["Server", "Process", "Lambda", "Datastore"],
        ["handlesResourceConsumption"],
    ),
    ("DS01", ["Server"], ["sanitizesInput", "validatesInput", "encodesOutput"]),
    ("DS03", ["Server"], ["isHardened"]),
    ("DS04", ["Server"], ["encodesOutput", "validatesInput", "sanitizesInput"]),
    ("SC02", ["Server"], ["validatesInput", "encodesOutput"]),
    (
        "SC03",
        ["Server"],
        ["validatesInput", "sanitizesInput", "hasAccessControl"],
    ),
    ("SC04", ["Server"], ["sanitizesInput", "validatesInput", "encodesOutput"]),
    ("SC05", ["Server"], ["providesIntegrity", "usesCodeSigning"]),
    ("HA03", ["Server"], ["validatesHeaders", "encodesOutput", "isHardened"]),
    ("AA01", ["Server", "Process"], ["authenticatesSource"]),
    ("AA02", ["Server", "Process"], ["authenticatesSource"]),
    (
        "AA03",
        ["Server"],
        ["providesIntegrity", "authenticatesSource", "usesStrongSessionIdentifiers"],
    ),
    ("CR03", ["Server", "Process"], ["implementsAuthenticationScheme"]),
    ("DE04", ["Datastore"], ["validatesInput", "implementsPOLP"]),
]
OR_PARAMS = [
    pytest.param(sid, kind, controls, id=f"{sid}-{kind}")
    for sid, kinds, controls in OR_RULES
    for kind in kinds
]


@pytest.mark.parametrize("sid,kind,controls", OR_PARAMS)
def test_or_rule_does_not_apply_when_all_controls_are_set(
    sid: str, kind: str, controls: list[str]
) -> None:
    threat = threats[sid]
    target = KINDS[kind]()
    assert threat.apply(target)  # default: controls missing
    set_controls(target, controls, True)
    assert not threat.apply(target)


@pytest.mark.parametrize("sid,kind,controls", OR_PARAMS)
def test_or_rule_applies_when_any_single_control_is_missing(
    sid: str, kind: str, controls: list[str]
) -> None:
    # Guards against a clause being dead: each control alone must matter.
    threat = threats[sid]
    for missing in controls:
        target = KINDS[kind]()
        set_controls(target, controls, True)
        assert not threat.apply(target)
        setattr(target.controls, missing, False)
        assert threat.apply(target), f"{sid}: {missing} has no effect"


@pytest.mark.parametrize("sid,kind,controls", OR_PARAMS)
def test_or_rule_does_not_apply_to_a_dataflow(
    sid: str, kind: str, controls: list[str]
) -> None:
    flow = make_flow()
    assert not threats[sid].apply(flow)


# ---------------------------------------------------------------------------
# implementsAPI rules
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kind", ["Process", "Lambda"])
def test_API01_does_not_apply_without_api(kind: str) -> None:
    threat = threats["API01"]
    target = KINDS[kind]()
    target.implementsAPI = True
    assert threat.apply(target)
    target.implementsAPI = False
    assert not threat.apply(target)


def test_API01_does_not_apply_to_server() -> None:
    server = Server("Web")
    assert not threats["API01"].apply(server)


@pytest.mark.parametrize("kind", ["Process", "Lambda"])
def test_API02_does_not_apply_without_api_or_with_validation(kind: str) -> None:
    threat = threats["API02"]
    target = KINDS[kind]()
    target.implementsAPI = True
    target.controls.validatesInput = False
    assert threat.apply(target)

    target.implementsAPI = False
    assert not threat.apply(target)

    target.implementsAPI = True
    target.controls.validatesInput = True
    assert not threat.apply(target)


@pytest.mark.parametrize("kind", ["Process", "Lambda"])
def test_LB01_does_not_apply_without_api_or_with_both_controls(kind: str) -> None:
    threat = threats["LB01"]
    target = KINDS[kind]()
    target.implementsAPI = True
    assert threat.apply(target)

    target.implementsAPI = False
    assert not threat.apply(target)

    target.implementsAPI = True
    target.controls.validatesInput = True
    assert threat.apply(target)  # sanitizesInput still missing
    target.controls.sanitizesInput = True
    assert not threat.apply(target)
    target.controls.validatesInput = False
    assert threat.apply(target)  # validatesInput alone is enough


# ---------------------------------------------------------------------------
# "and" rules on elements
# ---------------------------------------------------------------------------
def test_HA01_does_not_apply_if_either_control_is_set() -> None:
    threat = threats["HA01"]
    web = Server("Web")
    assert threat.apply(web)
    web.controls.validatesInput = True
    assert not threat.apply(web)
    web.controls.validatesInput = False
    web.controls.sanitizesInput = True
    assert not threat.apply(web)
    web.controls.validatesInput = True
    assert not threat.apply(web)


@pytest.mark.parametrize("sid", ["HA02", "HA04"])
def test_HA_physical_access_does_not_apply_without_physical_access(sid: str) -> None:
    threat = threats[sid]
    entity = ExternalEntity("EE")
    entity.hasPhysicalAccess = True
    assert threat.apply(entity)
    entity.hasPhysicalAccess = False
    assert not threat.apply(entity)


@pytest.mark.parametrize("sid", ["HA02", "HA04"])
def test_HA_physical_access_does_not_apply_to_server(sid: str) -> None:
    assert not threats[sid].apply(Server("Web"))


def test_AA04_does_not_apply_with_server_side_validation() -> None:
    threat = threats["AA04"]
    web = Server("Web")
    assert threat.apply(web)
    web.controls.implementsServerSideValidation = True
    assert not threat.apply(web)


def test_AA04_does_not_apply_if_integrity_and_authorization_are_set() -> None:
    threat = threats["AA04"]
    web = Server("Web")
    web.controls.providesIntegrity = True
    assert threat.apply(web)  # authorizesSource still missing
    web.controls.authorizesSource = True
    assert not threat.apply(web)
    web.controls.providesIntegrity = False
    assert threat.apply(web)


def test_AA04_does_not_apply_to_dataflow() -> None:
    assert not threats["AA04"].apply(make_flow())


def test_CR04_does_not_apply_without_session_tokens_or_with_nonce() -> None:
    threat = threats["CR04"]
    web = Server("Web")
    web.usesSessionTokens = True
    assert threat.apply(web)

    web.usesSessionTokens = False
    assert not threat.apply(web)

    web.usesSessionTokens = True
    web.controls.implementsNonce = True
    assert not threat.apply(web)


def test_CR04_does_not_apply_to_process() -> None:
    process = Process("Proc")
    assert not threats["CR04"].apply(process)


def test_SC01_does_not_apply_with_nonce_or_without_json() -> None:
    threat = threats["SC01"]
    process = Process("Proc")
    process.data = Data(name="JSON", description="some JSON", format="JSON")
    assert threat.apply(process)

    process.controls.implementsNonce = True
    assert not threat.apply(process)

    other = Process("Other")
    other.data = Data(name="Text", description="some text", format="plain")
    assert not threat.apply(other)

    no_data = Process("NoData")
    assert not threat.apply(no_data)


def test_SC01_does_not_apply_to_server() -> None:
    server = Server("Web")
    server.data = Data(name="JSON", description="some JSON", format="JSON")
    assert not threats["SC01"].apply(server)


@pytest.mark.parametrize("kind", ["Process", "Lambda"])
def test_DS02_does_not_apply_outside_production(kind: str) -> None:
    threat = threats["DS02"]
    target = KINDS[kind]()
    target.environment = "Production"
    assert threat.apply(target)
    target.environment = "Staging"
    assert not threat.apply(target)
    target.environment = ""
    assert not threat.apply(target)


def test_DS02_does_not_apply_to_server() -> None:
    assert not threats["DS02"].apply(Server("Web"))


def test_DS05_does_not_apply_without_cache() -> None:
    threat = threats["DS05"]
    web = Server("Web")
    web.usesCache = True
    assert threat.apply(web)
    web.usesCache = False
    assert not threat.apply(web)


def test_DS05_does_not_apply_to_process() -> None:
    assert not threats["DS05"].apply(Process("Proc"))


@pytest.mark.parametrize("kind", ["Server", "Datastore"])
@pytest.mark.parametrize("algorithm", ["RSA", "AES"])
def test_CR05_does_not_apply_with_approved_algorithm(kind: str, algorithm: str) -> None:
    threat = threats["CR05"]
    target = KINDS[kind]()
    target.controls.usesEncryptionAlgorithm = "DES"
    assert threat.apply(target)
    target.controls.usesEncryptionAlgorithm = algorithm
    assert not threat.apply(target)


def test_CR05_does_not_apply_to_process() -> None:
    process = Process("Proc")
    process.controls.usesEncryptionAlgorithm = "DES"
    assert not threats["CR05"].apply(process)


def test_DO05_does_not_apply_without_xml_parser() -> None:
    threat = threats["DO05"]
    web = Server("Web")
    web.usesXMLParser = True
    assert threat.apply(web)
    web.usesXMLParser = False
    assert not threat.apply(web)


def test_DO05_does_not_apply_when_input_is_validated_and_sanitized() -> None:
    threat = threats["DO05"]
    web = Server("Web")
    web.usesXMLParser = True
    web.controls.validatesInput = True
    assert threat.apply(web)  # sanitizesInput still missing
    web.controls.sanitizesInput = True
    assert not threat.apply(web)
    web.controls.validatesInput = False
    assert threat.apply(web)


def test_DO05_does_not_apply_to_process() -> None:
    assert not threats["DO05"].apply(Process("Proc"))


# ---------------------------------------------------------------------------
# Dataflow rules
# ---------------------------------------------------------------------------
def xml_flow(protocol: str = "HTTP") -> Dataflow:
    flow = make_flow()
    flow.protocol = protocol
    flow.data = Data(name="xml", description="textual", format="XML")
    return flow


@pytest.mark.parametrize("sid", ["DO03", "DO04"])
def test_DO_xml_does_not_apply_without_xml_data(sid: str) -> None:
    threat = threats[sid]
    flow = xml_flow()
    assert threat.apply(flow)

    json_flow = make_flow()
    json_flow.data = Data(name="json", description="textual", format="JSON")
    assert not threat.apply(json_flow)

    assert not threat.apply(make_flow())  # no data at all


@pytest.mark.parametrize("sid", ["DO03", "DO04"])
def test_DO_xml_does_not_apply_to_server(sid: str) -> None:
    assert not threats[sid].apply(Server("Web"))


def test_CR07_does_not_apply_without_http_or_without_xml() -> None:
    threat = threats["CR07"]
    flow = xml_flow("HTTP")
    assert threat.apply(flow)

    assert not threat.apply(xml_flow("HTTPS"))

    plain = make_flow()
    plain.protocol = "HTTP"
    plain.data = Data(name="json", description="textual", format="JSON")
    assert not threat.apply(plain)


def test_CR07_does_not_apply_to_server() -> None:
    assert not threats["CR07"].apply(Server("Web"))


def test_CR08_does_not_apply_with_encryption_and_adequate_tls() -> None:
    threat = threats["CR08"]
    web = Server("Web")
    web.minTLSVersion = TLSVersion.TLSv12
    flow = Dataflow(Actor("User"), web, "flow")
    flow.controls.isEncrypted = True
    flow.tlsVersion = TLSVersion.TLSv13
    assert not threat.apply(flow)

    flow.tlsVersion = TLSVersion.TLSv12  # equal to the minimum is acceptable
    assert not threat.apply(flow)

    flow.tlsVersion = TLSVersion.TLSv11
    assert threat.apply(flow)

    flow.tlsVersion = TLSVersion.TLSv13
    flow.controls.isEncrypted = False
    assert threat.apply(flow)


def test_CR08_does_not_apply_to_server() -> None:
    assert not threats["CR08"].apply(Server("Web"))


def test_DE03_does_not_apply_with_https_encryption_and_vpn() -> None:
    threat = threats["DE03"]
    flow = make_flow()
    flow.protocol = "HTTPS"
    flow.controls.isEncrypted = True
    flow.usesVPN = True
    assert not threat.apply(flow)

    flow.usesVPN = False
    assert threat.apply(flow)
    flow.usesVPN = True

    flow.protocol = "HTTP"
    assert threat.apply(flow)
    flow.protocol = "HTTPS"

    flow.controls.isEncrypted = False
    assert threat.apply(flow)


def test_DE03_does_not_apply_to_server() -> None:
    assert not threats["DE03"].apply(Server("Web"))


def test_CR06_does_not_apply_with_https_vpn_or_with_authn_and_authz() -> None:
    threat = threats["CR06"]
    flow = make_flow()
    flow.protocol = "HTTP"
    assert threat.apply(flow)

    # first clause: protocol is HTTPS *and* a VPN is used
    flow.protocol = "HTTPS"
    flow.usesVPN = True
    assert not threat.apply(flow)
    flow.usesVPN = False
    assert threat.apply(flow)
    flow.usesVPN = True
    flow.protocol = "HTTP"
    assert threat.apply(flow)  # not HTTPS, so still applies

    # second clause: both authentication and authorization are in place
    flow.controls.implementsAuthenticationScheme = True
    assert threat.apply(flow)  # authorizesSource still missing
    flow.controls.authorizesSource = True
    assert not threat.apply(flow)
    flow.controls.implementsAuthenticationScheme = False
    assert threat.apply(flow)


def test_CR06_does_not_apply_to_server() -> None:
    assert not threats["CR06"].apply(Server("Web"))


def test_CR01_does_not_apply_without_session_tokens() -> None:
    threat = threats["CR01"]
    web = Server("Web")
    web.protocol = "HTTP"
    web.usesSessionTokens = True
    flow = Dataflow(Actor("User"), web, "flow")
    flow.protocol = "HTTP"
    flow.usesSessionTokens = True
    assert threat.apply(web)
    assert threat.apply(flow)

    web.usesSessionTokens = False
    flow.usesSessionTokens = False
    assert not threat.apply(web)
    assert not threat.apply(flow)


def test_CR01_does_not_apply_with_https_over_vpn() -> None:
    threat = threats["CR01"]
    web = Server("Web")
    web.protocol = "HTTP"
    web.usesVPN = False
    web.usesSessionTokens = True
    flow = Dataflow(Actor("User"), web, "flow")
    flow.protocol = "HTTP"
    flow.usesSessionTokens = True
    assert threat.apply(web)
    assert threat.apply(flow)

    web.protocol = "HTTPS"
    web.usesVPN = True
    flow.protocol = "HTTPS"
    flow.usesVPN = True
    assert not threat.apply(web)
    assert not threat.apply(flow)

    # either clause alone keeps the threat alive
    flow.usesVPN = False
    assert threat.apply(flow)
    flow.usesVPN = True
    flow.protocol = "HTTP"
    assert threat.apply(flow)


def test_CR01_does_not_apply_to_process() -> None:
    process = Process("Proc")
    assert not threats["CR01"].apply(process)


def test_CR02_does_not_apply_without_http_or_session_tokens() -> None:
    threat = threats["CR02"]
    web = Server("Web")
    web.protocol = "HTTP"
    web.usesSessionTokens = True
    flow = Dataflow(Actor("User"), web, "flow")
    flow.protocol = "HTTP"
    flow.usesSessionTokens = True
    assert threat.apply(web)
    assert threat.apply(flow)

    web.protocol = "HTTPS"
    flow.protocol = "HTTPS"
    assert not threat.apply(web)
    assert not threat.apply(flow)

    web.protocol = "HTTP"
    flow.protocol = "HTTP"
    web.usesSessionTokens = False
    flow.usesSessionTokens = False
    assert not threat.apply(web)
    assert not threat.apply(flow)


def test_CR02_does_not_apply_when_input_is_validated_and_sanitized() -> None:
    threat = threats["CR02"]
    web = Server("Web")
    web.protocol = "HTTP"
    web.usesSessionTokens = True
    flow = Dataflow(Actor("User"), web, "flow")
    flow.protocol = "HTTP"
    flow.usesSessionTokens = True
    for target in (web, flow):
        assert threat.apply(target)
        target.controls.sanitizesInput = True
        assert threat.apply(target)  # validatesInput still missing
        target.controls.validatesInput = True
        assert not threat.apply(target)
        target.controls.sanitizesInput = False
        assert threat.apply(target)


def test_CR02_does_not_apply_to_process() -> None:
    process = Process("Proc")
    assert not threats["CR02"].apply(process)


# ---------------------------------------------------------------------------
# DE01: encryption, authentication of the destination, revocation, TLS version
# ---------------------------------------------------------------------------
def secure_flow() -> Dataflow:
    web = Server("Web")
    web.minTLSVersion = TLSVersion.TLSv12
    flow = Dataflow(Actor("User"), web, "flow")
    flow.tlsVersion = TLSVersion.TLSv13
    flow.controls.isEncrypted = True
    flow.controls.authenticatesDestination = True
    flow.controls.checksDestinationRevocation = True
    return flow


def test_DE01_does_not_apply_to_a_fully_secured_flow() -> None:
    assert not threats["DE01"].apply(secure_flow())


def test_DE01_applies_when_each_requirement_is_dropped() -> None:
    threat = threats["DE01"]

    flow = secure_flow()
    flow.controls.isEncrypted = False
    assert threat.apply(flow)

    flow = secure_flow()
    flow.controls.authenticatesDestination = False
    assert threat.apply(flow)

    flow = secure_flow()
    flow.controls.checksDestinationRevocation = False
    assert threat.apply(flow)

    flow = secure_flow()
    flow.tlsVersion = TLSVersion.TLSv11
    assert threat.apply(flow)


def test_DE01_does_not_apply_to_responses_or_out_of_scope_sources() -> None:
    threat = threats["DE01"]

    flow = secure_flow()
    flow.controls.authenticatesDestination = False
    assert threat.apply(flow)
    flow.isResponse = True
    assert not threat.apply(flow)

    flow = secure_flow()
    flow.controls.checksDestinationRevocation = False
    assert threat.apply(flow)
    flow.source.inScope = False
    assert not threat.apply(flow)


def test_DE01_does_not_apply_when_tls_equals_minimum() -> None:
    flow = secure_flow()
    flow.tlsVersion = TLSVersion.TLSv12
    assert not threats["DE01"].apply(flow)


def test_DE01_does_not_apply_to_server() -> None:
    assert not threats["DE01"].apply(Server("Web"))


# ---------------------------------------------------------------------------
# DS06: data classification above what source, sink or flow may carry
# ---------------------------------------------------------------------------
def classified_flow(
    source: Classification = Classification.RESTRICTED,
    sink: Classification = Classification.RESTRICTED,
    flow: Classification = Classification.RESTRICTED,
    data: Classification | None = Classification.RESTRICTED,
) -> Dataflow:
    src = Server("Source", maxClassification=source)
    dst = Datastore("Sink", maxClassification=sink)
    result = Dataflow(src, dst, "Flow", maxClassification=flow)
    if data is not None:
        result.data = Data("Data", classification=data)
    return result


def test_DS06_does_not_apply_without_data_or_when_classification_fits() -> None:
    threat = threats["DS06"]
    assert threat.apply(classified_flow(source=Classification.PUBLIC))
    assert not threat.apply(classified_flow(data=None))
    assert not threat.apply(classified_flow())
    assert not threat.apply(classified_flow(data=Classification.PUBLIC))


@pytest.mark.parametrize("limited", ["source", "sink", "flow"])
def test_DS06_applies_only_when_the_limiting_element_is_lower(limited: str) -> None:
    threat = threats["DS06"]
    kwargs = {limited: Classification.PUBLIC}
    assert threat.apply(classified_flow(**kwargs))
    assert not threat.apply(classified_flow(data=Classification.PUBLIC, **kwargs))


def test_DS06_does_not_apply_to_server() -> None:
    assert not threats["DS06"].apply(Server("Web"))


# ---------------------------------------------------------------------------
# DR01: sensitive data without protection
# ---------------------------------------------------------------------------
def pii_flow(encrypted: bool, stored: bool = False) -> Dataflow:
    flow = Dataflow(Server("Web"), Datastore("DB"), "insert")
    flow.data = Data("ssn", isPII=True, isStored=stored)
    flow.controls.isEncrypted = encrypted
    return flow


def test_DR01_does_not_apply_to_an_encrypted_flow_of_unstored_data() -> None:
    threat = threats["DR01"]
    assert threat.apply(pii_flow(encrypted=False))
    assert not threat.apply(pii_flow(encrypted=True))


def test_DR01_does_not_apply_without_sensitive_data() -> None:
    threat = threats["DR01"]
    flow = pii_flow(encrypted=False)
    assert threat.apply(flow)

    flow.data = Data("note", isPII=False, isCredentials=False)
    assert not threat.apply(flow)

    assert not threat.apply(Dataflow(Server("A"), Datastore("B"), "empty"))


def test_DR01_credentials_without_pii_also_count_as_sensitive() -> None:
    threat = threats["DR01"]
    flow = Dataflow(Server("Web"), Datastore("DB"), "login")
    flow.data = Data("password", isCredentials=True)
    assert threat.apply(flow)  # not encrypted
    flow.controls.isEncrypted = True
    assert not threat.apply(flow)


def test_DR01_does_not_apply_to_server() -> None:
    assert not threats["DR01"].apply(Server("Web"))
