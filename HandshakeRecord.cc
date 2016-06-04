#include "tls/HandshakeRecord.h"
#include "tls/HelloRequest.h"
#include "tls/ClientHello.h"
#include "tls/ServerHello.h"
#include "tls/ServerCertificate.h"
#include "tls/ServerHelloDone.h"
#include "tls/ServerKeyExchange.h"
#include "tls/ClientKeyExchange.h"
#include "tls/Finished.h"
#include "tls/ConnectionState.h"
#include "coder/Unsigned32.h"
#include "tls/exceptions/RecordException.h"

namespace CKTLS {

#ifdef _TLS_THREAD_LOCAL_
HandshakeRecord::HandshakeRecord()
: RecordProtocol(handshake),
  body(0) {
}
#else
HandshakeRecord::HandshakeRecord(StateContainer *hold)
: RecordProtocol(handshake),
  body(0),
  holder(hold) {
}
#endif

#ifdef _TLS_THREAD_LOCAL_
HandshakeRecord::HandshakeRecord(HandshakeType h)
: RecordProtocol(handshake),
  body(0),
  type(h) {
#else
HandshakeRecord::HandshakeRecord(HandshakeType h, StateContainer *hold)
: RecordProtocol(handshake),
  body(0),
  type(h),
  holder(hold) {
#endif

#ifdef _TLS_THREAD_LOCAL_
    ConnectionEnd end = ConnectionState::getPendingRead()->getEntity();
#else
    ConnectionEnd end = holder->getPendingRead()->getEntity();
#endif
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
#ifdef _TLS_THREAD_LOCAL_
            body = new ServerKeyExchange;
#else
            body = new ServerKeyExchange(holder);
#endif
            break;
        case client_key_exchange:
            if (end != client) {
                throw RecordException("Wrong connection state");
            }
            body = new ClientKeyExchange;
            break;
        case finished:
#ifdef _TLS_THREAD_LOCAL_
            body = new Finished;
#else
            body = new Finished(holder);
#endif
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
#ifdef _TLS_THREAD_LOCAL_
            body = new ServerKeyExchange;
#else
            body = new ServerKeyExchange(holder);
#endif
            break;
        case client_key_exchange:
            body = new ClientKeyExchange;
            break;
        case finished:
#ifdef _TLS_THREAD_LOCAL_
            body = new Finished;
#else
            body = new Finished(holder);
#endif
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
