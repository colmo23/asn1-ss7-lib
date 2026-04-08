"""
Transport layer — send TCAP messages over TCP or UDP (SIGTRAN stub).

Real SS7 signalling runs over SCTP/M3UA/SCCP. For lab/firewall testing
you have two options:
  1. Raw TCP/UDP to a STP or HLR simulator that accepts raw TCAP.
  2. Full SIGTRAN stack (M3UA → SCCP → TCAP) via osmo-ss7 or a commercial STP.

This module provides:
  - RawSender: plain TCP or UDP (works with most SS7 simulators / test nodes)
  - FileSender: write messages to a PCAP or hex file for replay with tcpreplay
"""

from __future__ import annotations
import socket
import struct
import time
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class RawSender:
    """Send raw TCAP payload over TCP or UDP."""

    def __init__(self, host: str, port: int, proto: str = "tcp",
                 timeout: float = 5.0, delay: float = 0.01):
        self.host    = host
        self.port    = port
        self.proto   = proto.lower()
        self.timeout = timeout
        self.delay   = delay
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        family = socket.AF_INET
        kind   = socket.SOCK_STREAM if self.proto == "tcp" else socket.SOCK_DGRAM
        self._sock = socket.socket(family, kind)
        self._sock.settimeout(self.timeout)
        if self.proto == "tcp":
            self._sock.connect((self.host, self.port))
        log.info("Connected to %s:%d (%s)", self.host, self.port, self.proto)

    def send(self, payload: bytes) -> None:
        if self._sock is None:
            self.connect()
        try:
            if self.proto == "tcp":
                self._sock.sendall(payload)
            else:
                self._sock.sendto(payload, (self.host, self.port))
        except OSError as exc:
            log.error("Send failed: %s", exc)
            self._sock = None
            raise

    def send_all(self, messages: list[bytes]) -> dict:
        sent = ok = err = 0
        for payload in messages:
            try:
                self.send(payload)
                ok += 1
            except OSError:
                err += 1
            sent += 1
            time.sleep(self.delay)
        return {"sent": sent, "ok": ok, "errors": err}

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()


class FileSender:
    """Write messages to a plain hex file or a minimal PCAP for tcpreplay."""

    def __init__(self, path: str, fmt: str = "hex"):
        self.path = Path(path)
        self.fmt  = fmt.lower()  # "hex" or "pcap"

    def write_hex(self, messages: list[tuple[str, bytes]]) -> None:
        with self.path.open("w") as fh:
            for name, payload in messages:
                fh.write(f"# {name}\n")
                fh.write(payload.hex() + "\n\n")
        log.info("Wrote %d messages to %s", len(messages), self.path)

    def write_pcap(self, messages: list[tuple[str, bytes]],
                   src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2",
                   src_port: int = 2905, dst_port: int = 2905) -> None:
        """
        Write a minimal PCAP (linktype ETHERNET / IPv4 / UDP).
        Each TCAP payload becomes one UDP datagram.
        """
        def ip_to_bytes(ip: str) -> bytes:
            return bytes(int(x) for x in ip.split("."))

        PCAP_GLOBAL_HEADER = struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,  # magic
            2, 4,         # version
            0,            # thiszone
            0,            # sigfigs
            65535,        # snaplen
            1,            # network (LINKTYPE_ETHERNET)
        )

        src_ip_b = ip_to_bytes(src_ip)
        dst_ip_b = ip_to_bytes(dst_ip)
        ts = int(time.time())

        with self.path.open("wb") as fh:
            fh.write(PCAP_GLOBAL_HEADER)
            for _name, payload in messages:
                udp_len    = 8 + len(payload)
                ip_len     = 20 + udp_len
                eth_frame  = (
                    b"\x00\x00\x00\x00\x00\x02"   # dst MAC
                    b"\x00\x00\x00\x00\x00\x01"   # src MAC
                    b"\x08\x00"                    # EtherType IPv4
                    # IPv4 header (no options)
                    + struct.pack(">BBHHHBBH4s4s",
                        0x45, 0, ip_len,
                        0, 0,
                        64, 17,   # TTL=64, proto=UDP
                        0,        # checksum (zero for simplicity)
                        src_ip_b, dst_ip_b,
                    )
                    # UDP header
                    + struct.pack(">HHHH",
                        src_port, dst_port, udp_len, 0)
                    + payload
                )
                rec_header = struct.pack("<IIII", ts, 0, len(eth_frame), len(eth_frame))
                fh.write(rec_header + eth_frame)
        log.info("Wrote %d packets to %s (PCAP)", len(messages), self.path)
