"""
Low-level TCAP BER builder.

TCAP message types (ITU-T Q.773):
  Begin        0x62
  Continue     0x65
  End          0x64
  Abort        0x67

Each is a constructed Application-class tag wrapping:
  otid / dtid       (Originating / Destination Transaction ID)
  DialoguePortion   (optional, 0x6b)
  ComponentPortion  (0x6c)
"""

from __future__ import annotations
import struct
import os
from enum import IntEnum


# ---------------------------------------------------------------------------
# Tag / length helpers
# ---------------------------------------------------------------------------

def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, length >> 8, length & 0xFF])
    else:
        raise ValueError(f"Length {length} too large")


def tlv(tag: int | bytes, value: bytes) -> bytes:
    """Encode a single TLV (handles multi-byte tags passed as bytes)."""
    if isinstance(tag, int):
        tag_bytes = bytes([tag])
    else:
        tag_bytes = tag
    return tag_bytes + _encode_length(len(value)) + value


def constructed(tag: int, *children: bytes) -> bytes:
    payload = b"".join(children)
    return tlv(tag, payload)


# ---------------------------------------------------------------------------
# Transaction ID helpers
# ---------------------------------------------------------------------------

def _tid(tid_int: int, length: int = 4) -> bytes:
    return tid_int.to_bytes(length, "big")


def random_tid() -> int:
    return int.from_bytes(os.urandom(4), "big")


# ---------------------------------------------------------------------------
# TCAP Application Context OID encoding
#
# Standard OID for GSM MAP v3:
#   0.4.0.0.1.0.22.3  (itu-t(0) identified-organization(4) etsi(0) mobileDomain(0)
#                       gsm-Network(1) applicationContexts(0) networkLocUp(22) version3(3))
# ---------------------------------------------------------------------------

def _encode_oid_subidentifier(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    parts = []
    while value:
        parts.append(value & 0x7F)
        value >>= 7
    parts.reverse()
    for i in range(len(parts) - 1):
        parts[i] |= 0x80
    return bytes(parts)


def encode_oid(arcs: list[int]) -> bytes:
    """Encode OID arcs to DER bytes (first two arcs combined as 40*a0+a1)."""
    encoded = _encode_oid_subidentifier(40 * arcs[0] + arcs[1])
    for arc in arcs[2:]:
        encoded += _encode_oid_subidentifier(arc)
    return tlv(0x06, encoded)


# MAP application context OIDs (ITU-T / 3GPP TS 29.002 annex K)
MAP_AC = {
    # name                         arcs (0.4.0.0.1.0.operationCode.version)
    "networkLocUp-v3":             [0, 4, 0, 0, 1, 0, 1, 3],
    "locationCancellation-v3":     [0, 4, 0, 0, 1, 0, 2, 3],
    "roamingNumberEnquiry-v3":     [0, 4, 0, 0, 1, 0, 3, 3],
    "sendRoutingInfo-v3":          [0, 4, 0, 0, 1, 0, 4, 3],
    "handoverControl-v3":          [0, 4, 0, 0, 1, 0, 6, 3],
    "equipmentMngt-v3":            [0, 4, 0, 0, 1, 0, 7, 3],
    "infoRetrieval-v5":            [0, 4, 0, 0, 1, 0, 8, 5],
    "interVlrInfoRetrieval-v3":    [0, 4, 0, 0, 1, 0, 9, 3],
    "subscriberDataMngt-v3":       [0, 4, 0, 0, 1, 0, 10, 3],
    "tracingContext-v3":           [0, 4, 0, 0, 1, 0, 11, 3],
    "networkFunctionalSs-v3":      [0, 4, 0, 0, 1, 0, 12, 3],
    "networkUnstructuredSs-v3":    [0, 4, 0, 0, 1, 0, 12, 3],
    "shortMsgGateway-v3":          [0, 4, 0, 0, 1, 0, 20, 3],
    "shortMsgMO-Relay-v3":         [0, 4, 0, 0, 1, 0, 21, 3],
    "shortMsgAlert-v3":            [0, 4, 0, 0, 1, 0, 23, 3],
    "shortMsgMT-Relay-v3":         [0, 4, 0, 0, 1, 0, 24, 3],
    "sendRoutingInfoForSM-v3":     [0, 4, 0, 0, 1, 0, 25, 3],
    "mwdMngt-v3":                  [0, 4, 0, 0, 1, 0, 26, 3],
    "lcsGml-v1":                   [0, 4, 0, 0, 1, 0, 29, 1],
    "lssMsLocReq-v1":              [0, 4, 0, 0, 1, 0, 30, 1],
    "callCompletion-v3":           [0, 4, 0, 0, 1, 0, 36, 3],
    "serviceTermination-v1":       [0, 4, 0, 0, 1, 0, 37, 1],
    "authenticationFailureReport-v3": [0, 4, 0, 0, 1, 0, 39, 3],
    "mm-EventReporting-v3":        [0, 4, 0, 0, 1, 0, 40, 3],
    "anyTimeInfo-v3":              [0, 4, 0, 0, 1, 0, 41, 3],
    "gprsLocationUpdate-v3":       [0, 4, 0, 0, 1, 0, 43, 3],
    "gprsLocationInfoRetrieval-v3":[0, 4, 0, 0, 1, 0, 44, 3],
    "failureReport-v3":            [0, 4, 0, 0, 1, 0, 45, 3],
    "msInfoProcedure-v3":          [0, 4, 0, 0, 1, 0, 47, 3],
    "isUbcForwardSM-v3":           [0, 4, 0, 0, 1, 0, 49, 3],
}

# CAP (CAMEL) application context OIDs (3GPP TS 29.078)
CAP_AC = {
    "cap3-gsmSSF-scfGenericAC":    [0, 4, 0, 0, 1, 21, 3, 50],
    "cap3-gsmSCF-gsmSRF-genericAC":[0, 4, 0, 0, 1, 21, 3, 51],
    "cap3-gprsSSF-scfGenericAC":   [0, 4, 0, 0, 1, 21, 3, 52],
    "cap4-gsmSSF-scfGenericAC":    [0, 4, 0, 0, 1, 21, 4, 50],
    "cap4-gsmSCF-gsmSRF-genericAC":[0, 4, 0, 0, 1, 21, 4, 51],
    "cap4-gprsSSF-scfGenericAC":   [0, 4, 0, 0, 1, 21, 4, 52],
}

# INAP CS-1 / CS-2 application context OIDs (ITU-T Q.1218 / Q.1228)
INAP_AC = {
    "cs1-scp-ccaf-ac":             [0, 4, 0, 0, 1, 20, 11, 1],
    "cs2-scp-ccaf-ac":             [0, 4, 0, 0, 1, 20, 11, 2],
}

ALL_AC = {**MAP_AC, **CAP_AC, **INAP_AC}


# ---------------------------------------------------------------------------
# Dialogue Portion  (EXTERNAL / AARQ)
# ---------------------------------------------------------------------------

DIALOGUE_AS_OID = [0, 0, 17, 773, 1, 1, 1]  # ITU-T dialogue-as-id

def build_aarq(ac_arcs: list[int]) -> bytes:
    """Build a TCAP DialoguePortion with AARQ (application association request)."""
    # AARQ-apdu  [APPLICATION 0] IMPLICIT SEQUENCE
    ac_oid = encode_oid(ac_arcs)
    application_context = tlv(0xa1, ac_oid)          # [1] EXPLICIT OID
    aarq_content = tlv(0x60, application_context)     # [APPLICATION 0] AARQ-apdu

    # EXTERNAL wrapper: direct-reference OID + encoding-choice (single-ASN1-type [2])
    dialog_as = encode_oid(DIALOGUE_AS_OID)
    encoding = tlv(0xa2, aarq_content)               # [2] single-ASN1-type
    external = constructed(0x28, dialog_as, encoding) # EXTERNAL (APPLICATION 8 → 0x28)

    return tlv(0x6b, external)                        # DialoguePortion tag


def build_aare(ac_arcs: list[int], result: int = 0) -> bytes:
    """AARE — used in Continue/End responses."""
    ac_oid = encode_oid(ac_arcs)
    result_tlv = tlv(0xa2, tlv(0x0a, bytes([result])))  # result ENUMERATED
    application_context = tlv(0xa1, ac_oid)
    aare_content = tlv(0x61, application_context + result_tlv)  # [APPLICATION 1] AARE-apdu
    dialog_as = encode_oid(DIALOGUE_AS_OID)
    encoding = tlv(0xa2, aare_content)
    external = constructed(0x28, dialog_as, encoding)
    return tlv(0x6b, external)


# ---------------------------------------------------------------------------
# Component helpers
# ---------------------------------------------------------------------------

class ComponentTag(IntEnum):
    INVOKE          = 0xa1
    RETURN_RESULT   = 0xa2
    RETURN_ERROR    = 0xa3
    REJECT          = 0xa4
    RETURN_RESULT_L = 0xa2  # Last


def _invoke_id(iid: int) -> bytes:
    return tlv(0x02, bytes([iid & 0xFF]))


def build_invoke(op_code: int, params: bytes, invoke_id: int = 1,
                 linked_id: int | None = None) -> bytes:
    iid = _invoke_id(invoke_id)
    lid = tlv(0x80, bytes([linked_id & 0xFF])) if linked_id is not None else b""
    op  = tlv(0x02, op_code.to_bytes(1 if op_code < 128 else 2, "big"))
    return tlv(ComponentTag.INVOKE, iid + lid + op + params)


def build_return_result(op_code: int, params: bytes, invoke_id: int = 1) -> bytes:
    iid = _invoke_id(invoke_id)
    op  = tlv(0x02, op_code.to_bytes(1 if op_code < 128 else 2, "big"))
    seq = tlv(0x30, op + params)     # SEQUENCE { opCode, result }
    return tlv(ComponentTag.RETURN_RESULT, iid + seq)


def build_return_error(error_code: int, params: bytes, invoke_id: int = 1) -> bytes:
    iid = _invoke_id(invoke_id)
    err = tlv(0x02, bytes([error_code & 0xFF]))
    return tlv(ComponentTag.RETURN_ERROR, iid + err + params)


def build_reject(invoke_id: int, problem_tag: int, problem_code: int) -> bytes:
    iid = _invoke_id(invoke_id)
    problem = tlv(bytes([problem_tag]), bytes([problem_code]))
    return tlv(ComponentTag.REJECT, iid + problem)


def component_portion(*components: bytes) -> bytes:
    return tlv(0x6c, b"".join(components))


# ---------------------------------------------------------------------------
# TCAP message builders
# ---------------------------------------------------------------------------

def begin(otid: int, dialogue: bytes, components: bytes) -> bytes:
    otid_tlv = tlv(0x48, _tid(otid))
    return constructed(0x62, otid_tlv, dialogue, components)


def continue_(otid: int, dtid: int, dialogue: bytes, components: bytes) -> bytes:
    otid_tlv = tlv(0x48, _tid(otid))
    dtid_tlv = tlv(0x49, _tid(dtid))
    return constructed(0x65, otid_tlv, dtid_tlv, dialogue, components)


def end(dtid: int, dialogue: bytes, components: bytes) -> bytes:
    dtid_tlv = tlv(0x49, _tid(dtid))
    return constructed(0x64, dtid_tlv, dialogue, components)


def abort(dtid: int, reason: int = 0) -> bytes:
    """TCAP Abort (P-Abort or U-Abort)."""
    dtid_tlv = tlv(0x49, _tid(dtid))
    p_abort  = tlv(0x4a, bytes([reason]))   # P-Abort cause
    return constructed(0x67, dtid_tlv, p_abort)
