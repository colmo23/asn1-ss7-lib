#!/usr/bin/env bash
# Download ASN.1 schemas from Wireshark GitHub (exact filenames)
set -e

BASE="https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/asn1"
SCHEMAS_DIR="$(dirname "$0")/schemas"

download() {
    local dir="$1"; shift
    mkdir -p "$SCHEMAS_DIR/$dir"
    for file in "$@"; do
        local dest="$SCHEMAS_DIR/$dir/$file"
        if [ ! -f "$dest" ]; then
            echo "  Fetching $dir/$file"
            curl -sSfL "$BASE/$dir/$file" -o "$dest" || echo "  WARNING: $dir/$file not found"
        else
            echo "  Skipping $dir/$file (exists)"
        fi
    done
}

echo "==> TCAP"
download tcap \
    TCAPMessages.asn \
    DialoguePDUs.asn \
    UnidialoguePDUs.asn \
    TC-Notation-Extensions.asn \
    tcap.asn

echo "==> MAP (gsm_map)"
download gsm_map \
    MAP-Protocol.asn \
    MAP-ApplicationContexts.asn \
    MAP-BS-Code.asn \
    MAP-CH-DataTypes.asn \
    MAP-CallHandlingOperations.asn \
    MAP-CommonDataTypes.asn \
    MAP-DialogueInformation.asn \
    MAP-ER-DataTypes.asn \
    MAP-Errors.asn \
    MAP-ExtensionDataTypes.asn \
    MAP-GR-DataTypes.asn \
    MAP-Group-Call-Operations.asn \
    MAP-LCS-DataTypes.asn \
    MAP-LocationServiceOperations.asn \
    MAP-MS-DataTypes.asn \
    MAP-MobileServiceOperations.asn \
    MAP-OM-DataTypes.asn \
    MAP-OperationAndMaintenanceOperations.asn \
    MAP-SM-DataTypes.asn \
    MAP-SS-Code.asn \
    MAP-SS-DataTypes.asn \
    MAP-ShortMessageServiceOperations.asn \
    MAP-SupplementaryServiceOperations.asn \
    MAP-TS-Code.asn \
    MobileDomainDefinitions.asn \
    GSMMAP.asn \
    SS-DataTypes.asn \
    SS-Errors.asn \
    SS-Operations.asn \
    SS-Protocol.asn \
    Ericsson.asn \
    Nokia.asn

echo "==> CAP (CAMEL)"
download camel \
    CAP-datatypes.asn \
    CAP-errorcodes.asn \
    CAP-errortypes.asn \
    CAP-operationcodes.asn \
    CAP-object-identifiers.asn \
    CAP-classes.asn \
    CAP-GPRS-ReferenceNumber.asn \
    CAP-SMS-ops-args.asn \
    CAP-U-ABORT-Data.asn \
    CAP-gprsSSF-gsmSCF-ops-args.asn \
    CAP-gsmSCF-gsmSRF-ops-args.asn \
    CAP-gsmSSF-gsmSCF-ops-args.asn \
    CamelV2diff.asn \
    TCAPMessages.asn \
    camel.asn

echo "==> INAP"
download inap \
    IN-SSF-SCF-datatypes.asn \
    IN-SSF-SCF-ops-args.asn \
    IN-SSF-SCF-Classes.asn \
    IN-SCF-SRF-datatypes.asn \
    IN-SCF-SRF-ops-args.asn \
    IN-SCF-SRF-Classes.asn \
    IN-common-datatypes.asn \
    IN-common-classes.asn \
    IN-errorcodes.asn \
    IN-errortypes.asn \
    IN-object-identifiers.asn \
    IN-operationcodes.asn \
    inap.asn

echo "Done. Schemas in $SCHEMAS_DIR"
