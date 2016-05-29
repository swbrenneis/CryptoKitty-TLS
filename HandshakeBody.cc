#include "HandshakeBody.h"

namespace CKTLS {

HandshakeBody::HandshakeBody() {
}

HandshakeBody::~HandshakeBody() {
}

void HandshakeBody::decode(const coder::ByteArray& stream) {

    encoded = stream;
    decode();

}

}

