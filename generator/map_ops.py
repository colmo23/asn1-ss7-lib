"""
MAP operation codes (3GPP TS 29.002) and parameter builders.

Operations are grouped by functional area matching the MAP ASN.1 module structure.
Each builder returns raw BER-encoded parameters (the payload inside an Invoke component).
"""

from __future__ import annotations
from .tcap import tlv, constructed


# ---------------------------------------------------------------------------
# MAP Operation Codes  (TS 29.002 §7.3 / Annex A)
# ---------------------------------------------------------------------------

class MapOp:
    # Mobility Management
    updateLocation                  = 2
    cancelLocation                  = 3
    purgeMS                         = 67
    sendIdentification              = 55
    updateGprsLocation              = 23
    provideRoamingNumber            = 4
    resumeCallHandling              = 6

    # Authentication
    sendAuthenticationInfo          = 56
    authenticationFailureReport     = 15

    # Subscriber Data Management
    insertSubscriberData            = 7
    deleteSubscriberData            = 8
    restoreData                     = 57

    # Fault Recovery
    reset                           = 37
    forwardCheckSsIndication        = 38
    failureReport                   = 45

    # Inter-VLR procedures
    prepareHandover                 = 68
    sendEndSignal                   = 29
    processAccessSignalling         = 33
    forwardAccessSignalling         = 34
    prepareSubsequentHandover       = 69

    # Short Message Service
    sendRoutingInfoForSM            = 45
    forwardShortMessage             = 46
    reportSMDeliveryStatus          = 47
    alertServiceCentre              = 64
    informServiceCentre             = 63
    sendRoutingInfoForSM_v1         = 45
    mo_forwardShortMessage          = 44
    mt_forwardShortMessage          = 46
    sendImsi                        = 58

    # Supplementary Services
    registerSS                      = 10
    eraseSS                         = 11
    activateSS                      = 12
    deactivateSS                    = 13
    interrogateSS                   = 14
    processUnstructuredSS_Request   = 59
    unstructuredSS_Request          = 60
    unstructuredSS_Notify           = 61
    registerPassword                = 17
    getPassword                     = 18

    # Call Handling
    sendRoutingInfo                 = 22
    provideSubscriberInfo           = 70
    anyTimeInterrogation            = 71
    anyTimeSubscriptionInterrogation= 62
    anyTimeModification             = 65
    noteSubscriberPresent           = 66
    noteInternalHandover            = 5

    # GPRS
    sendRoutingInfoForGprs          = 24
    failureReport_gprs              = 26
    noteMsPresentForGprs            = 27

    # Equipment Management
    checkImei                       = 43

    # Tracing
    activateTraceMode               = 50
    deactivateTraceMode             = 51
    sendImsi_tracing                = 58

    # Location Services
    provideSub_LocationInfo         = 83
    sendGroupCallEndSignal          = 31
    processGroupCallSignalling      = 32
    forwardGroupCallSignalling      = 36


# ---------------------------------------------------------------------------
# Commonly used type tags
# ---------------------------------------------------------------------------

ISDN_ADDRESS_STRING_TAG = 0x04   # OCTET STRING
IMSI_TAG                = 0x04
MSISDN_TAG              = 0x04
LAI_TAG                 = 0x04
LMSI_TAG                = 0x04


def _octet(tag: int, data: bytes) -> bytes:
    return tlv(tag, data)


def _integer(tag: int, value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return tlv(tag, value.to_bytes(length, "big"))


def _boolean(tag: int, value: bool) -> bytes:
    return tlv(tag, bytes([0xFF if value else 0x00]))


def _sequence(*children: bytes) -> bytes:
    return tlv(0x30, b"".join(children))


# ---------------------------------------------------------------------------
# Address encoding helpers (BCD semi-octet, TS 29.002 §7.1)
# ---------------------------------------------------------------------------

def encode_isdn_address(digits: str, nai: int = 0x91) -> bytes:
    """
    Encode an ISDN address string (MSISDN / GT) in BCD semi-octet format.
    nai: Nature of Address Indicator byte (0x91 = international)
    """
    if len(digits) % 2:
        digits += "F"
    pairs = [int(digits[i+1], 16) << 4 | int(digits[i], 16)
             for i in range(0, len(digits), 2)]
    return bytes([nai] + pairs)


def encode_imsi(digits: str) -> bytes:
    return encode_isdn_address(digits, nai=0x29)  # no ToN/NPI for IMSI


# ---------------------------------------------------------------------------
# Parameter builders
# ---------------------------------------------------------------------------

def params_update_location(imsi: str, msc_number: str, vlr_number: str) -> bytes:
    """UpdateLocation Arg (simplified, MAP v3)."""
    imsi_enc  = _octet(0x04, encode_imsi(imsi))
    msc_enc   = _octet(0x04, encode_isdn_address(msc_number))
    vlr_enc   = _octet(0x84, encode_isdn_address(vlr_number))  # [4] vlr-Number
    return _sequence(imsi_enc, msc_enc, vlr_enc)


def params_cancel_location(imsi: str) -> bytes:
    imsi_enc = _octet(0x04, encode_imsi(imsi))
    # cancellationType [0] CancellationType DEFAULT updateProcedure(0)
    cancel_type = tlv(0x82, b"\x00")
    return _sequence(imsi_enc, cancel_type)


def params_send_routing_info(msisdn: str) -> bytes:
    msisdn_enc  = _octet(0x84, encode_isdn_address(msisdn))  # [4] msisdn
    interr_type = tlv(0x85, b"\x00")                          # [5] interrogationType
    return _sequence(msisdn_enc, interr_type)


def params_send_routing_info_for_sm(msisdn: str, sm_rp_pri: bool = False) -> bytes:
    msisdn_enc = _octet(0x04, encode_isdn_address(msisdn))
    sm_rp      = _boolean(0x01, sm_rp_pri)
    service_centre = _octet(0x04, encode_isdn_address("12345678"))
    return _sequence(msisdn_enc, sm_rp, service_centre)


def params_forward_short_message(imsi: str, ms_isdn: str, sm_data: bytes) -> bytes:
    """mt-ForwardShortMessage / mo-ForwardShortMessage arg."""
    sm_rp_da = tlv(0xa0, _octet(0x04, encode_imsi(imsi)))    # [0] imsi
    sm_rp_oa = tlv(0xa2, _octet(0x04, encode_isdn_address(ms_isdn)))  # [2] serviceCentre
    sm_rp_ui = _octet(0x04, sm_data)
    return _sequence(sm_rp_da, sm_rp_oa, sm_rp_ui)


def params_insert_subscriber_data(imsi: str, msisdn: str) -> bytes:
    imsi_enc   = _octet(0x04, encode_imsi(imsi))
    msisdn_enc = _octet(0x01, encode_isdn_address(msisdn))   # [1] msisdn
    return _sequence(imsi_enc, msisdn_enc)


def params_delete_subscriber_data(imsi: str) -> bytes:
    imsi_enc = _octet(0x04, encode_imsi(imsi))
    # basicServiceList absent → delete all
    return _sequence(imsi_enc)


def params_send_authentication_info(imsi: str) -> bytes:
    imsi_enc    = _octet(0x04, encode_imsi(imsi))
    num_vectors = tlv(0x02, b"\x05")   # requestingNodeType not used in v2
    return _sequence(imsi_enc, num_vectors)


def params_provide_roaming_number(imsi: str, msc_number: str) -> bytes:
    imsi_enc = _octet(0x04, encode_imsi(imsi))
    msc_enc  = _octet(0x04, encode_isdn_address(msc_number))
    return _sequence(imsi_enc, msc_enc)


def params_update_gprs_location(imsi: str, sgsn_number: str) -> bytes:
    imsi_enc  = _octet(0x04, encode_imsi(imsi))
    sgsn_enc  = _octet(0x04, encode_isdn_address(sgsn_number))
    return _sequence(imsi_enc, sgsn_enc)


def params_check_imei(imei: str) -> bytes:
    imei_enc = _octet(0x04, encode_imsi(imei))  # same BCD encoding
    return _sequence(imei_enc)


def params_process_unstructured_ss(msisdn: str, ussd_string: str,
                                   language: int = 0x0F) -> bytes:
    """ProcessUnstructuredSS-Request."""
    ussd_dcs = _octet(0x04, bytes([language]))
    ussd_str = _octet(0x04, ussd_string.encode("utf-8"))
    return _sequence(ussd_dcs, ussd_str)


def params_provide_subscriber_info(imsi: str) -> bytes:
    imsi_enc      = _octet(0x04, encode_imsi(imsi))
    requested_info = tlv(0x30, tlv(0x80, b""))  # locationInformation
    return _sequence(imsi_enc, requested_info)


# ---------------------------------------------------------------------------
# MAP Error codes  (TS 29.002 §7.4)
# ---------------------------------------------------------------------------

class MapError:
    systemFailure               = 34
    dataMissing                 = 35
    unexpectedDataValue         = 36
    facilityNotSupported        = 21
    incompatibleTerminal        = 19
    resourceLimitation          = 51
    unknownSubscriber           = 1
    numberChanged               = 44
    unknownMSC                  = 3
    unidentifiedSubscriber      = 5
    absentSubscriber            = 27
    busySubscriber              = 45
    noSubscriberReply           = 46
    forwardingViolation         = 47
    forwardingFailed            = 48
    unauthorisedRequestingNetwork= 52
    illegalSS_Operation         = 16
    ss_ErrorStatus              = 17
    ss_NotAvailable             = 18
    ss_SubscriptionViolation    = 19
    ss_Incompatibility          = 20
    unknownAlphabet             = 71
    ussd_Busy                   = 72
    smDeliveryFailure           = 32
    messageWaitingListFull      = 33
    teleserviceNotProvisioned   = 6


# ---------------------------------------------------------------------------
# Full operation catalogue: op_code → (ac_name, param_builder, description)
# ---------------------------------------------------------------------------

OPERATION_CATALOGUE = {
    MapOp.updateLocation: (
        "networkLocUp-v3",
        lambda: params_update_location("001010123456789", "12345678", "87654321"),
        "UpdateLocation",
    ),
    MapOp.cancelLocation: (
        "locationCancellation-v3",
        lambda: params_cancel_location("001010123456789"),
        "CancelLocation",
    ),
    MapOp.sendRoutingInfo: (
        "sendRoutingInfo-v3",
        lambda: params_send_routing_info("491701234567"),
        "SendRoutingInfo",
    ),
    MapOp.sendRoutingInfoForSM: (
        "sendRoutingInfoForSM-v3",
        lambda: params_send_routing_info_for_sm("491701234567"),
        "SendRoutingInfoForSM",
    ),
    MapOp.mo_forwardShortMessage: (
        "shortMsgMO-Relay-v3",
        lambda: params_forward_short_message(
            "001010123456789", "12345678", b"\x00\x01\x00\x01test"
        ),
        "mo-ForwardShortMessage",
    ),
    MapOp.mt_forwardShortMessage: (
        "shortMsgMT-Relay-v3",
        lambda: params_forward_short_message(
            "001010123456789", "491701234567", b"\x00\x01\x00\x01test"
        ),
        "mt-ForwardShortMessage",
    ),
    MapOp.insertSubscriberData: (
        "subscriberDataMngt-v3",
        lambda: params_insert_subscriber_data("001010123456789", "491701234567"),
        "InsertSubscriberData",
    ),
    MapOp.deleteSubscriberData: (
        "subscriberDataMngt-v3",
        lambda: params_delete_subscriber_data("001010123456789"),
        "DeleteSubscriberData",
    ),
    MapOp.sendAuthenticationInfo: (
        "infoRetrieval-v5",
        lambda: params_send_authentication_info("001010123456789"),
        "SendAuthenticationInfo",
    ),
    MapOp.provideRoamingNumber: (
        "roamingNumberEnquiry-v3",
        lambda: params_provide_roaming_number("001010123456789", "12345678"),
        "ProvideRoamingNumber",
    ),
    MapOp.updateGprsLocation: (
        "gprsLocationUpdate-v3",
        lambda: params_update_gprs_location("001010123456789", "12345678"),
        "UpdateGprsLocation",
    ),
    MapOp.checkImei: (
        "equipmentMngt-v3",
        lambda: params_check_imei("490154203237518"),
        "CheckIMEI",
    ),
    MapOp.processUnstructuredSS_Request: (
        "networkUnstructuredSs-v3",
        lambda: params_process_unstructured_ss("491701234567", "*100#"),
        "ProcessUnstructuredSS-Request",
    ),
    MapOp.provideSubscriberInfo: (
        "infoRetrieval-v5",
        lambda: params_provide_subscriber_info("001010123456789"),
        "ProvideSubscriberInfo",
    ),
}
