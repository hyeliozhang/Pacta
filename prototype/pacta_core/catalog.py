"""Signed descriptor catalog and freshness checks for Pacta artifacts.

The paper's threat model assumes an owner-published descriptor.  This module
makes that boundary executable with deterministic HMAC signatures used in the
artifact.  It is not a replacement for production PKI; it exercises exactly the
freshness/replay invariants the verifier must check before accepting a query
certificate.
"""
from __future__ import annotations

import hashlib, hmac, json
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Mapping

JSON = Dict[str, Any]


def _strict_catalog_int(value: Any, name: str) -> int:
    """Return an owner-catalog integer without Python's lossy coercions.

    Freshness and version checks are security-critical request/owner bindings.
    Python's ``int`` would silently treat ``True`` as 1 and truncate 3.9 to 3;
    a verifier should reject those encodings rather than reinterpret them.  We
    accept JSON integers and decimal strings only because both appear in common
    artifact/config tooling, and reject booleans, floats, blanks, and nulls.
    """
    if isinstance(value, bool):
        raise ValueError(f"catalog field {name} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip() and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ValueError(f"catalog field {name} must be an integer")


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(tag: str, obj: Any) -> str:
    return hashlib.sha256((tag + "|" + canonical(obj)).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CatalogEntry:
    relation: str
    relation_version: int
    manifest_version: int
    epoch: int
    owner_digest: JSON
    relation_descriptor_digest: str
    manifest_root: str

    def payload(self) -> JSON:
        return asdict(self)


@dataclass(frozen=True)
class SignedCatalogEntry:
    entry: JSON
    signature: str
    key_id: str = "artifact-owner-key"
    scheme: str = "hmac-sha256-demo"

    def to_dict(self) -> JSON:
        return {"entry": self.entry, "signature": self.signature, "key_id": self.key_id, "scheme": self.scheme}


def sign_entry(entry: CatalogEntry, secret: bytes, *, key_id: str = "artifact-owner-key") -> SignedCatalogEntry:
    payload = entry.payload()
    sig = hmac.new(secret, canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()
    return SignedCatalogEntry(payload, sig, key_id=key_id)


def verify_signed_entry(signed: Mapping[str, Any], secret: bytes, *, min_epoch: int, expected_relation: str, expected_relation_version: int, expected_manifest_version: int) -> bool:
    try:
        entry = signed["entry"]
        sig = str(signed["signature"])
        calc = hmac.new(secret, canonical(entry).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, calc):
            return False
        if str(entry.get("relation")) != expected_relation:
            return False
        if _strict_catalog_int(entry.get("relation_version", None), "relation_version") != _strict_catalog_int(expected_relation_version, "expected_relation_version"):
            return False
        if _strict_catalog_int(entry.get("manifest_version", None), "manifest_version") != _strict_catalog_int(expected_manifest_version, "expected_manifest_version"):
            return False
        if _strict_catalog_int(entry.get("epoch", None), "epoch") < _strict_catalog_int(min_epoch, "min_epoch"):
            return False
        owner = entry.get("owner_digest", {})
        if owner.get("relation_descriptor_digest") != entry.get("relation_descriptor_digest"):
            return False
        if owner.get("manifest_root") != entry.get("manifest_root"):
            return False
        manifest_v = owner.get("manifest_release_version", owner.get("version", -999))
        if _strict_catalog_int(manifest_v, "owner.manifest_release_version") != _strict_catalog_int(expected_manifest_version, "expected_manifest_version"):
            return False
        if _strict_catalog_int(owner.get("relation_version", None), "owner.relation_version") != _strict_catalog_int(expected_relation_version, "expected_relation_version"):
            return False
        return True
    except Exception:
        return False


def catalog_root(signed_entries: Iterable[Mapping[str, Any]]) -> str:
    leaves = [digest("catalog_entry", x) for x in signed_entries]
    return digest("catalog_root", leaves)
