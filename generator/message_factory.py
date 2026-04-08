"""
MessageFactory — assembles complete TCAP messages for every MAP/CAP/INAP operation.

Usage:
    factory = MessageFactory()
    msgs = factory.generate_all()          # list of (name, bytes)
    msgs = factory.generate_map_begins()
    msgs = factory.generate_for_protocol("cap")
"""

from __future__ import annotations
import random
from dataclasses import dataclass

from .tcap import (
    random_tid, begin, continue_, end, abort,
    build_aarq, build_aare,
    build_invoke, build_return_result, build_return_error, build_reject,
    component_portion, ALL_AC, MAP_AC, CAP_AC, INAP_AC,
)
from .map_ops import OPERATION_CATALOGUE, MapOp, MapError


@dataclass
class GeneratedMessage:
    name: str
    protocol: str          # "map", "cap", "inap"
    msg_type: str          # "begin", "continue", "end", "abort"
    op_name: str
    raw: bytes

    def hex(self) -> str:
        return self.raw.hex()

    def __len__(self) -> int:
        return len(self.raw)


class MessageFactory:
    """Generate TCAP/MAP/CAP/INAP messages for every operation type."""

    def __init__(self, seed: int | None = None):
        if seed is not None:
            random.seed(seed)

    # ------------------------------------------------------------------
    # MAP message generation
    # ------------------------------------------------------------------

    def generate_map_begins(self) -> list[GeneratedMessage]:
        """One TCAP Begin per MAP operation in the catalogue."""
        messages = []
        for op_code, (ac_name, param_fn, op_name) in OPERATION_CATALOGUE.items():
            ac_arcs = MAP_AC.get(ac_name)
            if ac_arcs is None:
                continue
            otid = random_tid()
            dialogue = build_aarq(ac_arcs)
            invoke   = build_invoke(op_code, param_fn())
            comps    = component_portion(invoke)
            raw      = begin(otid, dialogue, comps)
            messages.append(GeneratedMessage(
                name=f"MAP-Begin-{op_name}",
                protocol="map",
                msg_type="begin",
                op_name=op_name,
                raw=raw,
            ))
        return messages

    def generate_map_continues(self) -> list[GeneratedMessage]:
        """Simulate mid-dialog Continues (e.g. InsertSubscriberData mid-auth)."""
        messages = []
        for op_code, (ac_name, param_fn, op_name) in OPERATION_CATALOGUE.items():
            ac_arcs = MAP_AC.get(ac_name)
            if ac_arcs is None:
                continue
            otid = random_tid()
            dtid = random_tid()
            dialogue = build_aare(ac_arcs)
            invoke   = build_invoke(op_code, param_fn(), invoke_id=2)
            comps    = component_portion(invoke)
            raw      = continue_(otid, dtid, dialogue, comps)
            messages.append(GeneratedMessage(
                name=f"MAP-Continue-{op_name}",
                protocol="map",
                msg_type="continue",
                op_name=op_name,
                raw=raw,
            ))
        return messages

    def generate_map_ends(self) -> list[GeneratedMessage]:
        """ReturnResult inside a TCAP End."""
        messages = []
        for op_code, (ac_name, param_fn, op_name) in OPERATION_CATALOGUE.items():
            ac_arcs = MAP_AC.get(ac_name)
            if ac_arcs is None:
                continue
            dtid     = random_tid()
            dialogue = build_aare(ac_arcs)
            rr       = build_return_result(op_code, param_fn())
            comps    = component_portion(rr)
            raw      = end(dtid, dialogue, comps)
            messages.append(GeneratedMessage(
                name=f"MAP-End-{op_name}",
                protocol="map",
                msg_type="end",
                op_name=op_name,
                raw=raw,
            ))
        return messages

    def generate_map_errors(self) -> list[GeneratedMessage]:
        """ReturnError for common MAP errors, inside a TCAP End."""
        error_cases = [
            (MapError.unknownSubscriber,   b"\x30\x00", "UnknownSubscriber"),
            (MapError.absentSubscriber,    b"\x30\x00", "AbsentSubscriber"),
            (MapError.systemFailure,       b"\x30\x00", "SystemFailure"),
            (MapError.dataMissing,         b"\x30\x00", "DataMissing"),
            (MapError.facilityNotSupported,b"\x30\x00", "FacilityNotSupported"),
            (MapError.smDeliveryFailure,   b"\x30\x05\x0a\x01\x00\x04\x00", "SMDeliveryFailure"),
            (MapError.teleserviceNotProvisioned, b"\x30\x00", "TeleserviceNotProvisioned"),
        ]
        messages = []
        ac_arcs = MAP_AC["networkLocUp-v3"]
        for err_code, err_params, err_name in error_cases:
            dtid     = random_tid()
            dialogue = build_aare(ac_arcs, result=1)
            re       = build_return_error(err_code, err_params)
            comps    = component_portion(re)
            raw      = end(dtid, dialogue, comps)
            messages.append(GeneratedMessage(
                name=f"MAP-Error-{err_name}",
                protocol="map",
                msg_type="end",
                op_name=f"Error-{err_name}",
                raw=raw,
            ))
        return messages

    def generate_map_aborts(self) -> list[GeneratedMessage]:
        messages = []
        for reason in range(5):
            dtid = random_tid()
            raw  = abort(dtid, reason=reason)
            messages.append(GeneratedMessage(
                name=f"MAP-Abort-reason{reason}",
                protocol="map",
                msg_type="abort",
                op_name=f"Abort-{reason}",
                raw=raw,
            ))
        return messages

    # ------------------------------------------------------------------
    # CAP (CAMEL) message generation
    # ------------------------------------------------------------------

    def generate_cap_begins(self) -> list[GeneratedMessage]:
        """Minimal CAP InitialDP (op 0) and other stubs for each CAP AC."""
        cap_ops = {
            0:  ("InitialDP",            b"\x30\x08\x80\x01\x01\x81\x01\x00\x82\x00"),
            23: ("EventReportBCSM",      b"\x30\x06\x80\x01\x06\x82\x01\x00"),
            24: ("ApplyCharging",        b"\x30\x08\xa0\x06\x80\x04\x00\x05\xf5\xe0"),
            31: ("Connect",              b"\x30\x09\xa0\x07\x80\x05\x91\x44\x97\x55\x00"),
            22: ("RequestReportBCSMEvent",b"\x30\x00"),
            33: ("ReleaseCall",          b"\x30\x03\x80\x01\x1f"),
        }
        messages = []
        for ac_name, ac_arcs in CAP_AC.items():
            for op_code, (op_name, params) in cap_ops.items():
                otid     = random_tid()
                dialogue = build_aarq(ac_arcs)
                invoke   = build_invoke(op_code, params)
                comps    = component_portion(invoke)
                raw      = begin(otid, dialogue, comps)
                messages.append(GeneratedMessage(
                    name=f"CAP-Begin-{ac_name}-{op_name}",
                    protocol="cap",
                    msg_type="begin",
                    op_name=op_name,
                    raw=raw,
                ))
        return messages

    # ------------------------------------------------------------------
    # INAP message generation
    # ------------------------------------------------------------------

    def generate_inap_begins(self) -> list[GeneratedMessage]:
        """INAP CS-1/CS-2 InitialDP and EventReportBCSM stubs."""
        inap_ops = {
            0:  ("InitialDP",        b"\x30\x06\x80\x01\x01\x82\x01\x00"),
            23: ("EventReportBCSM",  b"\x30\x04\x80\x01\x06\x82\x00"),
            20: ("ApplyCharging",    b"\x30\x04\xa0\x02\x80\x00"),
        }
        messages = []
        for ac_name, ac_arcs in INAP_AC.items():
            for op_code, (op_name, params) in inap_ops.items():
                otid     = random_tid()
                dialogue = build_aarq(ac_arcs)
                invoke   = build_invoke(op_code, params)
                comps    = component_portion(invoke)
                raw      = begin(otid, dialogue, comps)
                messages.append(GeneratedMessage(
                    name=f"INAP-Begin-{ac_name}-{op_name}",
                    protocol="inap",
                    msg_type="begin",
                    op_name=op_name,
                    raw=raw,
                ))
        return messages

    # ------------------------------------------------------------------
    # Fuzzing / malformed variants
    # ------------------------------------------------------------------

    def generate_fuzz_variants(self, base: bytes, count: int = 10) -> list[GeneratedMessage]:
        """Bit-flip and truncation fuzzing on an existing message."""
        variants = []
        for i in range(count):
            data = bytearray(base)
            mode = i % 3
            if mode == 0:
                # random byte flip
                pos = random.randint(0, len(data) - 1)
                data[pos] ^= random.randint(1, 0xFF)
            elif mode == 1:
                # truncate
                cut = random.randint(1, len(data))
                data = data[:cut]
            else:
                # insert random byte
                pos = random.randint(0, len(data))
                data.insert(pos, random.randint(0, 0xFF))
            variants.append(GeneratedMessage(
                name=f"Fuzz-{i}",
                protocol="fuzz",
                msg_type="fuzz",
                op_name="fuzz",
                raw=bytes(data),
            ))
        return variants

    # ------------------------------------------------------------------
    # Aggregate generators
    # ------------------------------------------------------------------

    def generate_all(self) -> list[GeneratedMessage]:
        return (
            self.generate_map_begins()
            + self.generate_map_continues()
            + self.generate_map_ends()
            + self.generate_map_errors()
            + self.generate_map_aborts()
            + self.generate_cap_begins()
            + self.generate_inap_begins()
        )

    def generate_for_protocol(self, protocol: str) -> list[GeneratedMessage]:
        proto = protocol.lower()
        if proto == "map":
            return (self.generate_map_begins() + self.generate_map_continues()
                    + self.generate_map_ends() + self.generate_map_errors()
                    + self.generate_map_aborts())
        elif proto == "cap":
            return self.generate_cap_begins()
        elif proto == "inap":
            return self.generate_inap_begins()
        else:
            raise ValueError(f"Unknown protocol: {protocol}")
