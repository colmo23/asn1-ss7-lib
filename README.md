# asn1-tester

A TCAP/MAP/CAP/INAP message generator for stress-testing SS7 message filtering and firewall applications. Generates valid BER-encoded TCAP messages covering every operation type across MAP, CAMEL (CAP), and INAP protocols.

---

## Overview

The tool produces 171 distinct TCAP messages (plus optional fuzz variants) using two complementary approaches:

- **Hand-crafted factory** — 96 messages: all four TCAP message types (Begin, Continue, End, Abort) × 14 MAP operations, plus CAP and INAP stubs with correct application context OIDs.
- **Schema-driven factory** — 75 messages: auto-generated from the actual 3GPP/ITU-T ASN.1 schemas (3GPP TS 29.002 MAP, TS 29.078 CAP, Q.1228 INAP) using `asn1tools` with BER encoding.

Output can be sent live over TCP/UDP or written to a hex file or PCAP for replay with `tcpreplay`.

---

## Protocols covered

| Protocol | Standard | Operations |
|---|---|---|
| **MAP** | 3GPP TS 29.002 | UpdateLocation, CancelLocation, SendRoutingInfo, SendRoutingInfoForSM, mo/mt-ForwardSM, InsertSubscriberData, DeleteSubscriberData, SendAuthenticationInfo, ProvideRoamingNumber, UpdateGprsLocation, CheckIMEI, ProcessUnstructuredSS, ProvideSubscriberInfo, ActivateTraceMode, PrepareHandover, AuthenticationFailureReport, SendIdentification, + more |
| **CAP (CAMEL)** | 3GPP TS 29.078 | InitialDP, Connect, ReleaseCall, RequestReportBCSMEvent, EventReportBCSM, ApplyCharging, ApplyChargingReport, CallGap, FurnishChargingInformation, PlayAnnouncement, InitialDPSMS, InitialDPGPRS, ApplyChargingGPRS, + more |
| **INAP** | ITU-T Q.1218/Q.1228 | InitialDP, Connect, EventReportBCSM, ApplyCharging, CollectInformation, SelectRoute, EstablishTemporaryConnection + more |

TCAP message types generated: **Begin**, **Continue**, **End** (ReturnResult), **End** (ReturnError), **Abort**

---

## Architecture

```
asn1-tester/
├── tcap_tester.py              # CLI entry point
├── fetch_schemas.sh            # Downloads ASN.1 schemas from Wireshark GitHub
├── requirements.txt
│
├── schemas/                    # ASN.1 schema files
│   ├── gsm_map/                # 32 MAP schemas (3GPP TS 29.002)
│   ├── camel/                  # 15 CAP/CAMEL schemas (3GPP TS 29.078)
│   ├── inap/                   # 13 INAP schemas (ITU-T Q.1218/Q.1228)
│   └── stubs/                  # Hand-written stubs for missing dependencies
│       ├── CS1-DataTypes.asn   # ETSI INAP CS1 types imported by CAP
│       ├── CS2-datatypes.asn   # ETSI INAP CS2 types imported by CAP
│       └── DirectoryAbstractService.asn
│
├── generator/
│   ├── tcap.py                 # BER TLV primitives; TCAP Begin/Continue/End/Abort builders
│   │                           # OID encoding; DialoguePortion (AARQ/AARE); Component builders
│   ├── map_ops.py              # MAP operation codes, BCD address encoding, parameter builders
│   ├── message_factory.py      # Hand-crafted factory (96 messages, all protocols)
│   ├── schema_generator.py     # Schema-driven factory; error-driven BER value builder
│   └── schema_loader.py        # ASN.1 preprocessor + compiler; pickle disk cache
│
├── transport/
│   └── sender.py               # RawSender (TCP/UDP); FileSender (hex, PCAP)
│
└── .schema_cache.pkl           # Compiled schema cache (auto-generated, ~10s first run)
```

### BER encoding

`generator/tcap.py` implements raw BER encoding without external dependencies:

- Multi-byte length encoding
- Application-class constructed tags for TCAP message types
- OID arc encoding for application contexts
- DialoguePortion wrapping (EXTERNAL / AARQ / AARE)
- Component encoding: Invoke, ReturnResult, ReturnError, Reject

### Schema loader

`generator/schema_loader.py` preprocesses the Wireshark-sourced ASN.1 schemas to remove constructs that `asn1tools` cannot handle:

- `CLASS` / `WITH SYNTAX` definitions (information object framework)
- Parameterized type definitions and applications (`Type{Params}`)
- ROSE `OPERATION ::= { ... }` and `ERROR ::= { ... }` blocks (only Arg/Res types needed)
- `INSTANCE OF`, `EMBEDDED PDV`, `CONTAINING`
- Size constraints using CLASS field references (`SIZE(bound.&min..bound.&max)` → `SIZE(1..255)`)

The compiled database (23 modules, 1004 types, 114 Arg types) is cached to `.schema_cache.pkl` after first compilation. Subsequent runs load in ~0.1s.

### Schema-driven value generation

`generator/schema_generator.py` uses an error-driven fill strategy to construct minimal valid BER values for each Arg type:

1. Start with `{}` (empty dict for Sequence, or appropriate primitive)
2. Encode → catch error → extract field name and expected Python type from error message
3. Add a sensible default for that field (bytes for OctetString, int for Integer, bool for Boolean, `(alt_name, value)` tuple for Choice)
4. Repeat until encoding succeeds or no progress

This avoids the need to walk the asn1tools internal type tree directly.

---

## Installation

```bash
# Install dependencies
pip install asn1tools

# Download ASN.1 schemas from Wireshark source tree (~64 files)
bash fetch_schemas.sh

# Verify (first run compiles schemas, ~10s; subsequent runs use cache)
python3 tcap_tester.py list
```

---

## Usage

### List all messages

```bash
# All 171 messages
python3 tcap_tester.py list

# Filter by protocol
python3 tcap_tester.py list --protocol map
python3 tcap_tester.py list --protocol cap
python3 tcap_tester.py list --protocol inap
```

### Generate message files

```bash
# Hex file (one message per entry, with name comment)
python3 tcap_tester.py generate --output messages.hex

# PCAP file for tcpreplay
python3 tcap_tester.py generate --output messages.pcap --fmt pcap

# MAP only
python3 tcap_tester.py generate --output map-only.hex --protocol map

# With 50 fuzz variants (bit-flips, truncations, insertions)
python3 tcap_tester.py generate --output fuzz.hex --fuzz 50

# Reproducible output
python3 tcap_tester.py generate --output messages.hex --seed 42
```

### Decode a hex message

```bash
# Inspect the TLV tree of any TCAP message
python3 tcap_tester.py decode 6259480349d2286b1a2818060700118605010101a00d600ba1090607040000010015036c36a13402010102012e302c8407911808390100008207911808390100010418b5000c915383060020900000a70be8329bfd06dddf723619

# Output:
# Outer tag: 0x62 → Begin
# Total length: 91 bytes
# Begin  tag=0x62  len=89
#   Appl[8]  tag=0x48  len=3   (otid)
#   Appl[11]  tag=0x6b  len=26  (DialoguePortion)
#   Appl[12]  tag=0x6c  len=54  (ComponentPortion)
#     Invoke  tag=0xa1  len=52
#       ...
```

### Send messages to a target

```bash
# Send all messages at 100 msg/s over TCP
python3 tcap_tester.py send --host 10.0.0.1 --port 2905 --rate 100

# UDP, MAP only
python3 tcap_tester.py send --host 10.0.0.1 --port 2905 --proto udp --protocol map

# Unlimited rate
python3 tcap_tester.py send --host 10.0.0.1 --port 2905 --rate 0
```

### Stress test

```bash
# Send 10000 random messages at 500/s
python3 tcap_tester.py stress --host 10.0.0.1 --port 2905 --count 10000 --rate 500

# CAP only stress test
python3 tcap_tester.py stress --host 10.0.0.1 --port 2905 --count 5000 --protocol cap
```

### Replay with tcpreplay

```bash
python3 tcap_tester.py generate --output messages.pcap --fmt pcap
sudo tcpreplay --intf1=eth0 --mbps=10 messages.pcap

# Loop indefinitely
sudo tcpreplay --intf1=eth0 --loop=0 --mbps=50 messages.pcap
```

---

## Message format details

### TCAP Application Context OIDs

Each message includes a DialoguePortion with an AARQ (application association request) identifying the operation class. Examples:

| AC name | OID | Used for |
|---|---|---|
| `networkLocUp-v3` | 0.4.0.0.1.0.1.3 | UpdateLocation |
| `sendRoutingInfoForSM-v3` | 0.4.0.0.1.0.25.3 | SendRoutingInfoForSM |
| `cap3-gsmSSF-scfGenericAC` | 0.4.0.0.1.21.3.50 | CAP Phase 3 voice |
| `cap3-gprsSSF-scfGenericAC` | 0.4.0.0.1.21.3.52 | CAP Phase 3 GPRS |
| `cs1-scp-ccaf-ac` | 0.4.0.0.1.20.11.1 | INAP CS-1 |

### TCAP message tags

| Tag | Message type |
|---|---|
| `0x62` | Begin |
| `0x65` | Continue |
| `0x64` | End |
| `0x67` | Abort |

### Component tags

| Tag | Component type |
|---|---|
| `0xa1` | Invoke |
| `0xa2` | ReturnResult |
| `0xa3` | ReturnError |
| `0xa4` | Reject |

---

## Transport notes

The tool sends raw TCAP payloads over TCP or UDP. For injection into a real SS7 network you need a SIGTRAN stack:

```
Application (this tool)
    ↓ raw TCAP bytes
SCCP (connectionless, called/calling GT)
    ↓
M3UA / SUA (SIGTRAN)
    ↓
SCTP
    ↓
STP / HLR / firewall DUT
```

Recommended tools for the SIGTRAN layer:
- **osmo-ss7** — open-source M3UA/SCCP stack (C), integrates with this tool via socket
- **SigPloit** — Python SS7 security test framework with M3UA/SCCP
- **Wireshark** — verify generated messages with the TCAP/MAP/CAMEL dissectors

---

## Extending

### Add a new MAP operation

In `generator/map_ops.py`, add the operation code to `MapOp` and a parameter builder function, then add an entry to `OPERATION_CATALOGUE`.

### Add a new protocol

1. Add ASN.1 schemas to `schemas/<protocol>/` (or run `fetch_schemas.sh` after updating it)
2. Add module paths to `ALL_MODULES` in `generator/schema_loader.py`
3. Add an AC OID dict (like `MAP_AC`) to `generator/tcap.py`
4. Add an op-code mapping dict (like `MAP_ARG_OPS`) to `generator/schema_generator.py`
5. Delete `.schema_cache.pkl` to trigger recompilation

### Rebuild schema cache

```bash
rm .schema_cache.pkl
python3 tcap_tester.py list   # recompiles on first access
```
