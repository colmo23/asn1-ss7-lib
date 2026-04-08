#!/usr/bin/env python3
"""
tcap_tester — TCAP/MAP/CAP/INAP message generator and stress tester.

Usage examples:
  # List all messages that would be generated
  python3 tcap_tester.py list

  # Generate all messages, write to hex file
  python3 tcap_tester.py generate --output messages.hex

  # Generate and write PCAP for tcpreplay
  python3 tcap_tester.py generate --output messages.pcap --fmt pcap

  # Send all MAP messages to a target
  python3 tcap_tester.py send --host 10.0.0.1 --port 2905 --proto tcp --filter map

  # Stress test: 1000 messages at 100/s
  python3 tcap_tester.py stress --host 10.0.0.1 --port 2905 --count 1000 --rate 100

  # Decode a hex message
  python3 tcap_tester.py decode 6259480349d2286b1a28...
"""

import argparse
import logging
import sys
import time

from generator.message_factory import MessageFactory
from generator.schema_generator import SchemaMessageFactory
from transport.sender import RawSender, FileSender


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------

def _get_messages(args):
    hand = MessageFactory()
    schema = SchemaMessageFactory()
    if args.protocol:
        msgs = hand.generate_for_protocol(args.protocol)
        msgs += [m for m in schema.generate_all() if m.protocol == args.protocol]
    else:
        msgs = hand.generate_all() + schema.generate_all()
    return msgs


def cmd_list(args):
    messages = _get_messages(args)

    print(f"{'#':<5} {'Name':<55} {'Proto':<6} {'Type':<10} {'Bytes'}")
    print("-" * 90)
    for i, msg in enumerate(messages, 1):
        print(f"{i:<5} {msg.name:<55} {msg.protocol:<6} {msg.msg_type:<10} {len(msg.raw)}")
    print(f"\nTotal: {len(messages)} messages")


# ---------------------------------------------------------------------------
# Subcommand: generate
# ---------------------------------------------------------------------------

def cmd_generate(args):
    messages = _get_messages(args)
    factory = MessageFactory(seed=args.seed)   # for fuzz variants only

    if args.fuzz:
        base = messages[0].raw if messages else b"\x62\x03\x48\x01\x01"
        fuzz_msgs = factory.generate_fuzz_variants(base, count=args.fuzz)
        messages.extend(fuzz_msgs)

    named = [(m.name, m.raw) for m in messages]
    sender = FileSender(args.output, fmt=args.fmt)

    if args.fmt == "pcap":
        sender.write_pcap(named)
    else:
        sender.write_hex(named)

    print(f"Generated {len(messages)} messages → {args.output}")


# ---------------------------------------------------------------------------
# Subcommand: send
# ---------------------------------------------------------------------------

def cmd_send(args):
    messages = _get_messages(args)

    payloads = [m.raw for m in messages]
    delay    = 1.0 / args.rate if args.rate > 0 else 0

    log.info("Sending %d messages to %s:%d (%s) at %.1f msg/s",
             len(payloads), args.host, args.port, args.proto, args.rate)

    with RawSender(args.host, args.port, args.proto, delay=delay) as sender:
        stats = sender.send_all(payloads)

    print(f"Done: {stats['ok']} sent, {stats['errors']} errors")


# ---------------------------------------------------------------------------
# Subcommand: stress
# ---------------------------------------------------------------------------

def cmd_stress(args):
    pool = _get_messages(args)

    if not pool:
        print("No messages generated.")
        return

    import random
    delay  = 1.0 / args.rate if args.rate > 0 else 0
    sent = ok = err = 0

    log.info("Stress test: %d total messages, pool size %d, %.1f msg/s",
             args.count, len(pool), args.rate)

    with RawSender(args.host, args.port, args.proto, delay=0) as sender:
        for _ in range(args.count):
            msg = random.choice(pool)
            try:
                sender.send(msg.raw)
                ok += 1
            except OSError as exc:
                log.warning("Send error: %s", exc)
                err += 1
            sent += 1
            if delay:
                time.sleep(delay)

    print(f"Stress done: {sent} sent, {ok} ok, {err} errors")


# ---------------------------------------------------------------------------
# Subcommand: decode (minimal TCAP tag inspector)
# ---------------------------------------------------------------------------

TCAP_MSG_TAGS = {
    0x62: "Begin",
    0x65: "Continue",
    0x64: "End",
    0x67: "Abort",
}

COMPONENT_TAGS = {
    0xa1: "Invoke",
    0xa2: "ReturnResult",
    0xa3: "ReturnError",
    0xa4: "Reject",
}


def _parse_length(data: bytes, offset: int) -> tuple[int, int]:
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    n = b & 0x7F
    length = int.from_bytes(data[offset+1:offset+1+n], "big")
    return length, offset + 1 + n


def decode_tlv_tree(data: bytes, indent: int = 0, offset: int = 0) -> None:
    while offset < len(data):
        if offset >= len(data):
            break
        tag = data[offset]; offset += 1
        length, offset = _parse_length(data, offset)
        value = data[offset:offset+length]
        is_constructed = bool(tag & 0x20)

        tag_class = {0x00: "Univ", 0x40: "Appl", 0x80: "Ctxt", 0xC0: "Priv"}[tag & 0xC0]
        tag_num   = tag & 0x1F
        label     = (TCAP_MSG_TAGS.get(tag) or COMPONENT_TAGS.get(tag)
                     or f"{tag_class}[{tag_num}]{'(c)' if is_constructed else ''}")

        print(f"{'  ' * indent}{label}  tag=0x{tag:02x}  len={length}")

        if is_constructed and len(value) > 0:
            decode_tlv_tree(value, indent + 1)
        else:
            preview = value[:16].hex()
            if len(value) > 16:
                preview += "..."
            print(f"{'  ' * (indent+1)}{preview}")

        offset += length


def cmd_decode(args):
    try:
        raw = bytes.fromhex(args.hex.replace(" ", ""))
    except ValueError as exc:
        print(f"Invalid hex: {exc}")
        sys.exit(1)

    outer_tag = raw[0]
    print(f"Outer tag: 0x{outer_tag:02x} → {TCAP_MSG_TAGS.get(outer_tag, 'Unknown')}")
    print(f"Total length: {len(raw)} bytes\n")
    decode_tlv_tree(raw)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="TCAP/MAP/CAP/INAP message generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    # list
    pl = sub.add_parser("list", help="List all messages that would be generated")
    pl.add_argument("--protocol", choices=["map", "cap", "inap"],
                    help="Filter by protocol")

    # generate
    pg = sub.add_parser("generate", help="Write messages to file")
    pg.add_argument("--output", default="messages.hex", help="Output file path")
    pg.add_argument("--fmt", choices=["hex", "pcap"], default="hex")
    pg.add_argument("--protocol", choices=["map", "cap", "inap"])
    pg.add_argument("--fuzz", type=int, metavar="N",
                    help="Append N fuzz variants of the first message")
    pg.add_argument("--seed", type=int, help="RNG seed for reproducible output")

    # send
    ps = sub.add_parser("send", help="Send messages to a target host")
    ps.add_argument("--host", required=True)
    ps.add_argument("--port", type=int, default=2905)
    ps.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    ps.add_argument("--rate", type=float, default=100,
                    help="Messages per second (0=unlimited)")
    ps.add_argument("--protocol", choices=["map", "cap", "inap"])

    # stress
    pst = sub.add_parser("stress", help="Randomised stress test")
    pst.add_argument("--host", required=True)
    pst.add_argument("--port", type=int, default=2905)
    pst.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    pst.add_argument("--count", type=int, default=1000)
    pst.add_argument("--rate", type=float, default=100,
                     help="Messages per second (0=unlimited)")
    pst.add_argument("--protocol", choices=["map", "cap", "inap"])

    # decode
    pd = sub.add_parser("decode", help="Inspect a hex-encoded TCAP message")
    pd.add_argument("hex", help="Hex string (spaces allowed)")

    args = p.parse_args()
    dispatch = {
        "list":     cmd_list,
        "generate": cmd_generate,
        "send":     cmd_send,
        "stress":   cmd_stress,
        "decode":   cmd_decode,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
