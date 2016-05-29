#include "Alert.h"
#include "exceptions/RecordException.h"

namespace CKTLS {

Alert::Alert()
: RecordProtocol(alert) {
}

Alert::Alert(AlertDescription d, AlertLevel l)
: RecordProtocol(alert),
  desc(d),
  level(l) {
}

Alert::~Alert() {
}

void Alert::decode() {

    switch (fragment[0]) {
        case fatal:
        case warning:
            level = static_cast<AlertLevel>(fragment[0]);
            break;
        default:
            throw RecordException("Invalid alert level");
    }

    switch (fragment[1]) {
        case close_notify:
        case unexpected_message:
        case bad_record_mac:
        case decryption_failed_RESERVED:
        case record_overflow:
        case decompression_failure:
        case handshake_failure:
        case no_certificate_RESERVED:
        case bad_certificate:
        case unsupported_certificate:
        case certificate_revoked:
        case certificate_expired:
        case certificate_unknown:
        case illegal_parameter:
        case unknown_ca:
        case access_denied:
        case decode_error:
        case decrypt_error:
        case export_restriction_RESERVED:
        case protocol_version:
        case insufficient_security:
        case internal_error:
        case user_canceled:
        case no_renegotiation:
        case unsupported_extension:
            desc = static_cast<AlertDescription>(fragment[1]);
            break;
        default:
            throw RecordException("Invalid alert description");
    }

}

void Alert::encode() {

    fragment.setLength(2);
    fragment[0] = level;
    fragment[1] = desc;

}

AlertDescription Alert::getDescription() const {

    return desc;

}

AlertLevel Alert::getLevel() const {

    return level;

}

void Alert::setDescription(AlertDescription d) {

    desc = d;

}

void Alert::setLevel(AlertLevel l) {

    level = l;

}

}
