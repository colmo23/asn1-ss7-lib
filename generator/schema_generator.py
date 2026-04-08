"""
Schema-driven message generator.

Uses the compiled ASN.1 database to enumerate every *Arg type,
create a minimal valid value for it, encode it to BER, then wrap
it in a TCAP Begin/End message with the correct application context.

For types that cannot be auto-generated (too many mandatory fields,
missing DEFAULT values, etc.) we fall back to the hand-crafted
encodings from map_ops.py.
"""

from __future__ import annotations
import os
import re
import random
from dataclasses import dataclass, field

from .schema_loader import get_db
from .tcap import (
    random_tid, begin, continue_, end, abort,
    build_aarq, build_aare,
    build_invoke, build_return_result, build_return_error,
    component_portion, MAP_AC, CAP_AC, INAP_AC,
    encode_oid,
)


# ---------------------------------------------------------------------------
# Operation → application context mapping
# Keyed on the *prefix* of the Arg type name.
# ---------------------------------------------------------------------------

# MAP op-code table:  ArgTypeName → (op_code, ac_name)
MAP_ARG_OPS: dict[str, tuple[int, str]] = {
    "UpdateLocationArg":                   (2,  "networkLocUp-v3"),
    "CancelLocationArg":                   (3,  "locationCancellation-v3"),
    "PurgeMS-Arg":                         (67, "networkLocUp-v3"),
    "SendIdentificationArg":               (55, "networkLocUp-v3"),
    "UpdateGprsLocationArg":               (23, "gprsLocationUpdate-v3"),
    "ProvideSubscriberInfoArg":            (70, "infoRetrieval-v5"),
    "AnyTimeInterrogationArg":             (71, "anyTimeInfo-v3"),
    "AnyTimeSubscriptionInterrogationArg": (62, "infoRetrieval-v5"),
    "AnyTimeModificationArg":              (65, "anyTimeInfo-v3"),
    "NoteSubscriberDataModifiedArg":       (5,  "networkLocUp-v3"),
    "PrepareHO-Arg":                       (68, "handoverControl-v3"),
    "SendEndSignal-Arg":                   (29, "handoverControl-v3"),
    "ProcessAccessSignalling-Arg":         (33, "handoverControl-v3"),
    "ForwardAccessSignalling-Arg":         (34, "handoverControl-v3"),
    "PrepareSubsequentHO-Arg":             (69, "handoverControl-v3"),
    "SendAuthenticationInfoArg":           (56, "infoRetrieval-v5"),
    "AuthenticationFailureReportArg":      (15, "authenticationFailureReport-v3"),
    "CheckIMEI-Arg":                       (43, "equipmentMngt-v3"),
    "InsertSubscriberDataArg":             (7,  "subscriberDataMngt-v3"),
    "DeleteSubscriberDataArg":             (8,  "subscriberDataMngt-v3"),
    "ResetArg":                            (37, "networkLocUp-v3"),
    "RestoreDataArg":                      (57, "networkLocUp-v3"),
    "SendRoutingInfoForGprsArg":           (24, "gprsLocationInfoRetrieval-v3"),
    "FailureReportArg":                    (25, "failureReport-v3"),
    "NoteMsPresentForGprsArg":             (26, "gprsLocationUpdate-v3"),
    "NoteMM-EventArg":                     (89, "mm-EventReporting-v3"),
    "UpdateVcsgLocationArg":               (53, "networkLocUp-v3"),
    "CancelVcsgLocationArg":               (36, "locationCancellation-v3"),
    "ActivateTraceModeArg":                (50, "tracingContext-v3"),
    "DeactivateTraceModeArg":              (51, "tracingContext-v3"),
    "SendRoutingInfoArg":                  (22, "sendRoutingInfo-v3"),
    "ProvideRoamingNumberArg":             (4,  "roamingNumberEnquiry-v3"),
    "ResumeCallHandlingArg":               (6,  "sendRoutingInfo-v3"),
    "SetReportingStateArg":                (73, "sendRoutingInfo-v3"),
    "StatusReportArg":                     (74, "sendRoutingInfo-v3"),
    "RemoteUserFreeArg":                   (75, "sendRoutingInfo-v3"),
    "IST-AlertArg":                        (87, "sendRoutingInfo-v3"),
    "IST-CommandArg":                      (88, "sendRoutingInfo-v3"),
    "ReleaseResourcesArg":                 (20, "sendRoutingInfo-v3"),
    "PrepareGroupCallArg":                 (39, "networkLocUp-v3"),
    "SendGroupCallEndSignalArg":           (40, "networkLocUp-v3"),
    "ProcessGroupCallSignallingArg":       (41, "networkLocUp-v3"),
    "ForwardGroupCallSignallingArg":       (42, "networkLocUp-v3"),
    "SendGroupCallInfoArg":                (84, "networkLocUp-v3"),
    "RoutingInfoForLCS-Arg":              (85, "lssMsLocReq-v1"),
    "ProvideSubscriberLocation-Arg":      (83, "lssMsLocReq-v1"),
    "SubscriberLocationReport-Arg":       (86, "lssMsLocReq-v1"),
    "RoutingInfoForSM-Arg":               (45, "sendRoutingInfoForSM-v3"),
    "MO-ForwardSM-Arg":                   (44, "shortMsgMO-Relay-v3"),
    "MT-ForwardSM-Arg":                   (46, "shortMsgMT-Relay-v3"),
    "ReportSM-DeliveryStatusArg":         (47, "shortMsgGateway-v3"),
    "AlertServiceCentreArg":              (64, "shortMsgAlert-v3"),
    "InformServiceCentreArg":             (63, "shortMsgMT-Relay-v3"),
    "ReadyForSM-Arg":                     (66, "shortMsgAlert-v3"),
    "MT-ForwardSM-VGCS-Arg":             (21, "shortMsgMT-Relay-v3"),
    "RegisterSS-Arg":                     (10, "networkFunctionalSs-v3"),
    "USSD-Arg":                           (59, "networkUnstructuredSs-v3"),
    "SS-InvocationNotificationArg":       (72, "networkFunctionalSs-v3"),
    "RegisterCC-EntryArg":                (76, "networkFunctionalSs-v3"),
    "EraseCC-EntryArg":                   (77, "networkFunctionalSs-v3"),
}

# CAP op-code table
CAP_ARG_OPS: dict[str, tuple[int, str]] = {
    "InitialDPArg":                       (0,  "cap3-gsmSSF-scfGenericAC"),
    "AssistRequestInstructionsArg":       (16, "cap3-gsmSSF-scfGenericAC"),
    "EstablishTemporaryConnectionArg":    (17, "cap3-gsmSSF-scfGenericAC"),
    "DisconnectForwardConnectionArg":     (18, "cap3-gsmSSF-scfGenericAC"),
    "ConnectToResourceArg":              (19, "cap3-gsmSSF-scfGenericAC"),
    "ConnectArg":                         (20, "cap3-gsmSSF-scfGenericAC"),
    "RequestReportBCSMEventArg":          (23, "cap3-gsmSSF-scfGenericAC"),
    "EventReportBCSMArg":                 (24, "cap3-gsmSSF-scfGenericAC"),
    "CollectInformationArg":             (27, "cap3-gsmSSF-scfGenericAC"),
    "ContinueWithArgumentArg":            (88, "cap3-gsmSSF-scfGenericAC"),
    "InitiateCallAttemptArg":            (32, "cap3-gsmSSF-scfGenericAC"),
    "ResetTimerArg":                      (33, "cap3-gsmSSF-scfGenericAC"),
    "FurnishChargingInformationArg":      (34, "cap3-gsmSSF-scfGenericAC"),
    "ApplyChargingArg":                   (35, "cap3-gsmSSF-scfGenericAC"),
    "ApplyChargingReportArg":             (36, "cap3-gsmSSF-scfGenericAC"),
    "CallGapArg":                         (41, "cap3-gsmSSF-scfGenericAC"),
    "CallInformationReportArg":           (44, "cap3-gsmSSF-scfGenericAC"),
    "CallInformationRequestArg":          (45, "cap3-gsmSSF-scfGenericAC"),
    "SendChargingInformationArg":         (46, "cap3-gsmSSF-scfGenericAC"),
    "PlayAnnouncementArg":               (47, "cap3-gsmSCF-gsmSRF-genericAC"),
    "PromptAndCollectUserInformationArg": (48, "cap3-gsmSCF-gsmSRF-genericAC"),
    "SpecializedResourceReportArg":       (49, "cap3-gsmSCF-gsmSRF-genericAC"),
    "CancelArg":                          (53, "cap3-gsmSSF-scfGenericAC"),
    "InitialDPSMSArg":                   (60, "cap3-gsmSSF-scfGenericAC"),
    "ConnectSMSArg":                     (62, "cap3-gsmSSF-scfGenericAC"),
    "RequestReportSMSEventArg":          (63, "cap3-gsmSSF-scfGenericAC"),
    "EventReportSMSArg":                 (64, "cap3-gsmSSF-scfGenericAC"),
    "FurnishChargingInformationSMSArg":  (61, "cap3-gsmSSF-scfGenericAC"),
    "ReleaseSMSArg":                     (66, "cap3-gsmSSF-scfGenericAC"),
    "ResetTimerSMSArg":                  (67, "cap3-gsmSSF-scfGenericAC"),
    "ApplyChargingGPRSArg":              (71, "cap3-gprsSSF-scfGenericAC"),
    "ApplyChargingReportGPRSArg":        (72, "cap3-gprsSSF-scfGenericAC"),
    "CancelGPRSArg":                     (73, "cap3-gprsSSF-scfGenericAC"),
    "ConnectGPRSArg":                    (74, "cap3-gprsSSF-scfGenericAC"),
    "ContinueGPRSArg":                   (75, "cap3-gprsSSF-scfGenericAC"),
    "EntityReleasedGPRSArg":             (76, "cap3-gprsSSF-scfGenericAC"),
    "FurnishChargingInformationGPRSArg": (77, "cap3-gprsSSF-scfGenericAC"),
    "InitialDPGPRSArg":                  (78, "cap3-gprsSSF-scfGenericAC"),
    "ReleaseGPRSArg":                    (79, "cap3-gprsSSF-scfGenericAC"),
    "EventReportGPRSArg":                (80, "cap3-gprsSSF-scfGenericAC"),
    "RequestReportGPRSEventArg":         (81, "cap3-gprsSSF-scfGenericAC"),
    "ResetTimerGPRSArg":                 (82, "cap3-gprsSSF-scfGenericAC"),
    "SendChargingInformationGPRSArg":    (83, "cap3-gprsSSF-scfGenericAC"),
}

# INAP op-codes (from IN-operationcodes.asn)
INAP_ARG_OPS: dict[str, tuple[int, str]] = {
    "InitialDPArg":                       (0,  "cs1-scp-ccaf-ac"),
    "AssistRequestInstructionsArg":       (16, "cs1-scp-ccaf-ac"),
    "EstablishTemporaryConnectionArg":    (17, "cs1-scp-ccaf-ac"),
    "DisconnectForwardConnectionArg":     (18, "cs1-scp-ccaf-ac"),
    "ConnectToResourceArg":              (19, "cs1-scp-ccaf-ac"),
    "ConnectArg":                         (20, "cs1-scp-ccaf-ac"),
    "HoldCallInNetworkArg":              (21, "cs1-scp-ccaf-ac"),
    "RequestReportBCSMEventArg":          (23, "cs1-scp-ccaf-ac"),
    "EventReportBCSMArg":                 (24, "cs1-scp-ccaf-ac"),
    "RequestNotificationChargingEventArg":(25, "cs1-scp-ccaf-ac"),
    "EventNotificationChargingArg":      (26, "cs1-scp-ccaf-ac"),
    "CollectInformationArg":             (27, "cs1-scp-ccaf-ac"),
    "AnalyseInformationArg":             (28, "cs1-scp-ccaf-ac"),
    "SelectRouteArg":                    (29, "cs1-scp-ccaf-ac"),
    "SelectFacilityArg":                 (30, "cs1-scp-ccaf-ac"),
    "ResetTimerArg":                     (33, "cs1-scp-ccaf-ac"),
    "FurnishChargingInformationArg":     (34, "cs1-scp-ccaf-ac"),
    "ApplyChargingArg":                  (35, "cs1-scp-ccaf-ac"),
    "ApplyChargingReportArg":            (36, "cs1-scp-ccaf-ac"),
    "CallGapArg":                        (41, "cs1-scp-ccaf-ac"),
    "CallInformationReportArg":          (44, "cs1-scp-ccaf-ac"),
    "CallInformationRequestArg":         (45, "cs1-scp-ccaf-ac"),
    "SendChargingInformationArg":        (46, "cs1-scp-ccaf-ac"),
    "PlayAnnouncementArg":               (47, "cs1-scp-ccaf-ac"),
    "PromptAndCollectUserInformationArg":(48, "cs1-scp-ccaf-ac"),
    "SpecializedResourceReportArg":      (49, "cs1-scp-ccaf-ac"),
    "CancelArg":                         (53, "cs1-scp-ccaf-ac"),
}


# ---------------------------------------------------------------------------
# Minimal value auto-generator
# ---------------------------------------------------------------------------

def _encode_arg(db, type_name: str) -> bytes | None:
    """
    Encode a minimal valid instance of type_name to BER.

    Uses an error-driven fill strategy: start with an empty dict, catch
    encoder errors, add sensible defaults for missing/wrong-typed fields,
    and retry. Handles nested Sequences, Choice types, and Enumerations.
    Path-aware: correctly populates nested sub-dicts rather than the top level.
    """
    # Default values keyed by partial field name (lower-case match)
    FIELD_DEFAULTS: list[tuple[str, object]] = [
        ('imsi',              b'\x00\x10\x10\x12\x34\x56\x78\x9f'),
        ('msisdn',            b'\x91\x44\x97\x00\x00\x00'),
        ('isdn',              b'\x91\x44\x97\x00\x00\x00'),
        ('address',           b'\x91\x44\x97\x00\x00\x00'),
        ('number',            b'\x91\x44\x97\x00\x00\x00'),
        ('digits',            b'\x01\x21\x43\x65'),
        ('cause',             b'\x80'),
        ('reference',         b'\x00\x00'),
        ('type',              0),
        ('mode',              0),
        ('category',          b'\x0a'),
        ('indicator',         b'\x00'),
        ('status',            0),
        ('id',                0),
        ('timer',             0),
        ('class',             0),
        ('code',              b'\x00'),
        ('key',               0),
        ('info',              b'\x00'),
        ('data',              b'\x00'),
        ('report',            0),
        ('result',            0),
        ('characteristic',    b'\x00'),
        ('charging',          b'\x00'),
        ('send',              False),
        ('forbidden',         False),
        ('notification',      False),
        ('complete',          False),
        ('started',           False),
        ('request',           False),
    ]

    def _default_for_field(name: str) -> object:
        nl = name.lower()
        for key, dflt in FIELD_DEFAULTS:
            if key in nl:
                return dflt
        return b'\x00'   # last resort

    def _type_default(type_hint: str):
        """Return a sensible default for a given Python type hint string."""
        th = type_hint.lower()
        if 'bool' in th:
            return False
        if 'tuple(bytes' in th:
            return (b'\x00', 0)        # BitString: (bytes, unused_bits)
        if 'tuple' in th:
            return ('', b'\x00')       # Choice placeholder; alt fixed by next error
        if 'dict' in th:
            return {}                  # Nested Sequence
        if 'list' in th:
            return []
        if 'int or str' in th:
            return 0                   # prefer int over str for INTEGER types
        if 'int' in th and 'str' not in th:
            return 0
        if 'str' in th:
            return 'unknown'           # will be corrected by enumeration handler
        if 'bytes' in th:
            return b'\x00'
        if 'none' in th:
            return None
        return b'\x00'

    import re as _re

    # --- helpers for navigating / mutating the nested val structure -----------

    def _parse_path(msg: str) -> tuple[list[str], str]:
        """
        Extract (field_path, error_body) from an asn1tools error message.
        Format: "TypeName[.field1[.field2]...]: error_body"
        Returns path as list of field names AFTER the type name.
        """
        m = _re.match(r'[\w-]+((?:\.[\w-]+)*):\s*(.*)', msg, _re.DOTALL)
        if m:
            path_str, body = m.group(1), m.group(2)
            path = [p for p in path_str.split('.') if p]
            return path, body
        return [], msg

    def _get_container(root, path: list[str]):
        """Navigate into nested dicts/Choices following path. Returns the innermost container."""
        cur = root
        for key in path:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            elif isinstance(cur, tuple) and len(cur) == 2 and cur[0] == key:
                # Key matches the Choice alt name — navigate to its inner value
                cur = cur[1]
            elif isinstance(cur, tuple) and len(cur) == 2:
                # Choice with a different alt; try navigating into the inner value
                inner = cur[1]
                if isinstance(inner, dict) and key in inner:
                    cur = inner[key]
                else:
                    return None
            else:
                return None
        return cur

    def _set_in_container(root, path: list[str], field: str, value) -> bool:
        """Set root[path[0]][path[1]]...[field] = value. Returns True if successful."""
        container = _get_container(root, path)
        if isinstance(container, dict):
            container[field] = value
            return True
        return False

    def _get_in_container(root, path: list[str], field: str):
        """Get root[path[0]][path[1]]...[field]. Returns None if not found."""
        container = _get_container(root, path)
        if isinstance(container, dict):
            return container.get(field)
        return None

    # -------------------------------------------------------------------------

    val = {}
    seen_errors: set[str] = set()

    for _attempt in range(80):
        try:
            return db.encode(type_name, val)
        except Exception as exc:
            msg = str(exc)

            if msg in seen_errors:
                break
            seen_errors.add(msg)

            path, body = _parse_path(msg)

            # ---- "Sequence member 'X' not found" ----
            m_seq = _re.search(r"[Ss]equence member '([\w-]+)' not found", body)
            if m_seq:
                field = m_seq.group(1)
                if not isinstance(val, dict):
                    break
                # Check if already set (shouldn't retry same error then)
                existing = _get_in_container(val, path, field)
                if existing is None:
                    _set_in_container(val, path, field, _default_for_field(field))
                continue

            # ---- "member 'X' not found" (generic) ----
            m_mem = _re.search(r"member '([\w-]+)' not found", body)
            if m_mem:
                field = m_mem.group(1)
                if isinstance(val, dict):
                    existing = _get_in_container(val, path, field)
                    if existing is None:
                        _set_in_container(val, path, field, _default_for_field(field))
                continue

            # ---- "Mandatory member 'X'" ----
            m_mand = _re.search(r"[Mm]andatory member '([\w-]+)'", body)
            if m_mand:
                field = m_mand.group(1)
                if isinstance(val, dict):
                    _set_in_container(val, path, field, _default_for_field(field))
                continue

            # ---- "Expected choice 'alt1' or 'alt2', but got X" ----
            m_choice = _re.search(r"Expected choice '([\w-]+)'", body)
            if m_choice:
                alt = m_choice.group(1)
                if not path and not isinstance(val, dict):
                    # Top-level Choice
                    inner = val[1] if isinstance(val, tuple) and len(val) == 2 else b'\x00'
                    val = (alt, inner)
                elif not path:
                    # Top-level but val is a dict — shouldn't happen, but handle
                    val = (alt, b'\x00')
                else:
                    # Nested Choice — path[-1] is the field name, path[:-1] is its parent
                    parent_path = path[:-1]
                    field = path[-1]
                    container = _get_container(val, parent_path) if parent_path else val
                    if isinstance(container, dict):
                        cur = container.get(field)
                        if isinstance(cur, tuple) and len(cur) == 2:
                            container[field] = (alt, cur[1])
                        else:
                            container[field] = (alt, b'\x00')
                continue

            # ---- "Expected data of type X, but got Y" ----
            m_type = _re.search(r"Expected data of type ([\w(),\s]+), but got", body)
            if m_type:
                type_hint = m_type.group(1)
                new_val = _type_default(type_hint)

                if not path:
                    # Top-level type mismatch
                    if val != new_val:
                        val = new_val
                    continue

                # Nested field — path[-1] is the field name
                parent_path = path[:-1]
                field = path[-1]
                container = _get_container(val, parent_path) if parent_path else val

                if isinstance(container, dict):
                    cur = container.get(field)
                    if isinstance(cur, tuple) and len(cur) == 2 and 'tuple' in type_hint.lower():
                        # Choice inner type mismatch: fix the inner value
                        inner = _type_default(type_hint)
                        if inner != cur[1]:
                            container[field] = (cur[0], inner)
                            continue
                    elif container.get(field) != new_val:
                        container[field] = new_val
                        continue
                elif isinstance(container, tuple) and len(container) == 2 and container[0] == field:
                    # container is a Choice; path[-1] is the alt name.
                    # Update its inner value via the grandparent dict.
                    gp_path = path[:-2]
                    choice_key = path[-2] if len(path) >= 2 else None
                    grandparent = _get_container(val, gp_path) if gp_path else val
                    if choice_key and isinstance(grandparent, dict):
                        grandparent[choice_key] = (field, new_val)
                    elif isinstance(val, tuple) and len(val) == 2:
                        val = (val[0], new_val)
                    continue
                elif container is None and isinstance(val, tuple) and len(val) == 2:
                    # Top-level tuple; update inner value
                    val = (val[0], new_val)
                continue

            # ---- "Expected None, but got X" (NULL-type Choice alts) ----
            m_null = _re.search(r"Expected None, but got", body)
            if m_null:
                if isinstance(val, tuple) and len(val) == 2:
                    # Top-level Choice with NULL inner value
                    val = (val[0], None)
                elif isinstance(val, dict) and len(path) == 1:
                    val[path[0]] = None
                continue

            # ---- "Expected enumeration value 'X' or 'Y'" ----
            m_enum = _re.search(r"Expected enumeration value '([\w-]+)'", body)
            if m_enum:
                first_val = m_enum.group(1)
                if not path:
                    val = first_val
                else:
                    parent_path = path[:-1]
                    field = path[-1]
                    container = _get_container(val, parent_path) if parent_path else val
                    if isinstance(container, dict):
                        container[field] = first_val
                continue

            # ---- Constraint violation: try padding bytes or incrementing int ----
            m_constraint = _re.search(
                r"(constraint|minimum|maximum|size)", body, _re.I
            )
            if m_constraint and path:
                parent_path = path[:-1]
                field = path[-1]
                container = _get_container(val, parent_path) if parent_path else val
                if isinstance(container, dict):
                    cur = container.get(field)
                    if isinstance(cur, bytes) and len(cur) < 20:
                        container[field] = cur + b'\x00'
                        continue
                    elif isinstance(cur, int):
                        container[field] = cur + 1
                        continue

            break
    return None


# ---------------------------------------------------------------------------
# Schema-driven message factory
# ---------------------------------------------------------------------------

@dataclass
class SchemaMessage:
    name: str
    protocol: str
    msg_type: str
    op_name: str
    raw: bytes

    def hex(self) -> str:
        return self.raw.hex()

    def __len__(self) -> int:
        return len(self.raw)


class SchemaMessageFactory:
    """
    Generate TCAP messages for every Arg type in the compiled schema database.
    """

    def __init__(self, verbose: bool = False):
        self.db = get_db(verbose=verbose)
        self._arg_types = self._enumerate_arg_types()

    def _enumerate_arg_types(self) -> list[tuple[str, str, str]]:
        """Returns list of (module_name, type_name, protocol)."""
        if not self.db:
            return []
        result = []
        for mod_name, module in self.db.modules.items():
            if 'CAP' in mod_name or 'cap' in mod_name or mod_name.startswith('CS'):
                proto = 'cap'
            elif 'IN-' in mod_name or 'IN_' in mod_name:
                proto = 'inap'
            else:
                proto = 'map'
            for type_name in module:
                if 'Arg' in type_name:
                    result.append((mod_name, type_name, proto))
        return result

    def _build_begin(self, op_code: int, ac_name: str,
                     arg_bytes: bytes, proto: str) -> bytes | None:
        ac_map = {'map': MAP_AC, 'cap': CAP_AC, 'inap': INAP_AC}
        ac_arcs = ac_map.get(proto, {}).get(ac_name)
        if ac_arcs is None:
            # Try all tables
            for tbl in (MAP_AC, CAP_AC, INAP_AC):
                ac_arcs = tbl.get(ac_name)
                if ac_arcs:
                    break
        if ac_arcs is None:
            return None
        otid     = random_tid()
        dialogue = build_aarq(ac_arcs)
        invoke   = build_invoke(op_code, arg_bytes)
        comps    = component_portion(invoke)
        return begin(otid, dialogue, comps)

    def generate_all(self) -> list[SchemaMessage]:
        messages: list[SchemaMessage] = []
        if not self.db:
            return messages

        all_ops = {**MAP_ARG_OPS, **CAP_ARG_OPS, **INAP_ARG_OPS}

        for mod_name, type_name, proto in self._arg_types:
            # Encode the argument
            arg_bytes = _encode_arg(self.db, type_name)
            if arg_bytes is None:
                continue

            # Look up operation code and AC
            op_info = all_ops.get(type_name)
            if op_info is None:
                # Try stripping trailing version suffix
                base = re.sub(r'-v\d+$', '', type_name)
                op_info = all_ops.get(base)

            if op_info is None:
                continue

            op_code, ac_name = op_info
            raw = self._build_begin(op_code, ac_name, arg_bytes, proto)
            if raw is None:
                continue

            messages.append(SchemaMessage(
                name=f"{proto.upper()}-Schema-{type_name}",
                protocol=proto,
                msg_type="begin",
                op_name=type_name,
                raw=raw,
            ))

        return messages

    def summary(self) -> dict:
        if not self.db:
            return {"status": "no database"}
        return {
            "modules": len(self.db.modules),
            "total_types": sum(len(m) for m in self.db.modules.values()),
            "arg_types": len(self._arg_types),
        }
