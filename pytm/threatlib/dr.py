"""DR threat definitions."""

from __future__ import annotations

import pytm
from pytm.enums import Lifetime
from pytm.threat import Threat

class DR01(Threat):
    """Unprotected Sensitive Data."""

    id: str = 'DR01'
    target: tuple = (pytm.Dataflow,)
    description: str = 'Unprotected Sensitive Data'
    details: str = 'An attacker can access data in transit or at rest that is not sufficiently protected. If an attacker can decrypt a stored password, it might be used to authenticate against different services.'
    likelihood: str = "Low"
    severity: str = "High"
    mitigations: str = 'All data should be encrypted in transit. All PII and restricted data must be encrypted at rest. If a service is storing credentials used to authenticate users or incoming connections, it must only store hashes of them created using cryptographic functions, so it is only possible to compare them against user input, without fully decoding them. If a client is storing credentials in either files or other data store, access to them must be as restrictive as possible, including using proper file permissions, database users with restricted access or separate storage.'
    references: str = 'https://cwe.mitre.org/data/definitions/311.html, https://cwe.mitre.org/data/definitions/312.html, https://cwe.mitre.org/data/definitions/916.html, https://cwe.mitre.org/data/definitions/653.html'

    def _check_condition(self, target) -> bool:
        return (target.hasDataLeaks() or any(d.isCredentials or d.isPII for d in target.data)) and (not target.controls.isEncrypted or (not target.isResponse and any(d.isStored and d.isDestEncryptedAtRest for d in target.data)) or (target.isResponse and any(d.isStored and d.isSourceEncryptedAtRest for d in target.data)))
