#include "HandshakeRecord.h"
#include "HelloRequest.h"
#include "ClientHello.h"
#include "ServerHello.h"
#include "ServerCertificate.h"
#include "ServerHelloDone.h"
#include "ServerKeyExchange.h"
#include "ClientKeyExchange.h"
#include "Finished.h"
#include "ConnectionState.h"
#include "coder/Unsigned32.h"
#include "exceptions/RecordException.h"

namespace CKTLS {

HandshakeRecord::HandshakeRecord()
: RecordProtocol(handshake),
  body(0) {
}

HandshakeRecord::HandshakeRecord(HandshakeType h)
: RecordProtocol(handshake),
  body(0),
  type(h) {

    ConnectionEnd end = ConnectionState::getPendingRead()->getEntity();

    switch (type) {
        case hello_request:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new HelloRequest;
            break;
        case client_hello:
            if (end != client) {
                throw RecordException("Wrong connection state");
            }
            body = new ClientHello;
            break;
        case certificate:
            if (end == server) {
                body = new ServerCertificate;
            }
            else {
                // TODO: Client certificate.
                body = 0;
            }
            break;
        case server_hello:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new ServerHello;
            break;
        case server_hello_done:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new ServerHelloDone;
            break;
        case server_key_exchange:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new ServerKeyExchange;
            break;
        case client_key_exchange:
            if (end != client) {
                throw RecordException("Wrong connection state");
            }
            body = new ClientKeyExchange;
            break;
        case finished:
            body = new Finished;
            break;
        default:
            throw RecordException("Invalid handshake type");
    }
    body->initState();

}

HandshakeRecord::~HandshakeRecord() {

    delete body;
}

/*
 * Decode a byte stream.
 */
void HandshakeRecord::decode() {

    type = static_cast<HandshakeType>(fragment[0]);
    // Decode the 24 bit body length.
    coder::ByteArray bLen(1, 0);
    bLen.append(fragment.range(1, 3));
    coder::Unsigned32 bodyLen(bLen, coder::bigendian);
    uint32_t length = bodyLen.getValue();
    if (length + 4 != fragment.getLength()) {
        throw RecordException("Invalid body length");
    }


    switch (type) {
        case hello_request:
            body = new HelloRequest;
            break;
        case certificate:
            body = new ServerCertificate;
            break;
        case client_hello:
            body = new ClientHello;
            break;
        case server_hello:
            body = new ServerHello;
            break;
        case server_hello_done:
            body = new ServerHelloDone;
            break;
        case server_key_exchange:
            body = new ServerKeyExchange;
            break;
        case client_key_exchange:
            body = new ClientKeyExchange;
            break;
        case finished:
            body = new Finished;
            break;
        default:
            throw RecordException("Invalid handshake type");
    }

    body->decode(fragment.range(4, length));

}

void HandshakeRecord::encode() {

    fragment.clear();
    fragment.append(type);
    coder::ByteArray encoded(body->encode());
    coder::Unsigned32 bodyLen(encoded.getLength());
    coder::ByteArray bl(bodyLen.getEncoded(coder::bigendian));
    fragment.append(bl.range(1, 3));    // 24 bit length.
    fragment.append(encoded);

}

HandshakeBody *HandshakeRecord::getBody() {

    return body;

}

HandshakeType HandshakeRecord::getHandshakeType() const {

    return type;

}

}
