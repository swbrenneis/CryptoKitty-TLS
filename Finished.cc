#include "tls/Finished.h"
#include "tls/ConnectionState.h"
#include "mac/HMAC.h"
#include "digest/SHA256.h"
#include "digest/SHA384.h"
#include "digest/SHA512.h"
#include "tls/exceptions/RecordException.h"

namespace CKTLS {

Finished::Finished() {
}

Finished::~Finished() {
}

bool Finished::authenticate(const coder::ByteArray& fin) const {

    ConnectionState *state = ConnectionState::getCurrentRead();
    MACAlgorithm mac = state->getHMAC();
    CK::Digest *digest;
    switch (mac) {
        case hmac_md5:
            // TODO
            break;
        case hmac_sha1:
            // TODO
            break;
        case hmac_sha256:
            digest = new CK::SHA256;
            break;
        case hmac_sha384:
            digest = new CK::SHA384;
            break;
        case hmac_sha512:
            digest = new CK::SHA512;
            break;
        default:
            throw RecordException("Invalid HMAC algorithm");
    }

    ConnectionEnd end = state->getEntity();
    coder::ByteArray seed(end == server ? "server finished" : "client finished");
    coder::ByteArray hash(digest->digest(fin));
    seed.append(hash);

    digest->reset();
    CK::HMAC hmac(digest);
    uint32_t keyLength = state->getMacKeyLength();
    coder::ByteArray key(state->getMasterSecret());
    hmac.setMessage(seed);
    hmac.setKey(key.range(0, keyLength));

    return hmac.authenticate(finished);

}

void Finished::decode() {

    finished = encoded;

}

const coder::ByteArray& Finished::encode() {

    encoded.clear();

    ConnectionState *state = ConnectionState::getCurrentWrite();
    MACAlgorithm mac = state->getHMAC();
    CK::Digest *digest;
    switch (mac) {
        case hmac_md5:
            // TODO
            break;
        case hmac_sha1:
            // TODO
            break;
        case hmac_sha256:
            digest = new CK::SHA256;
            break;
        case hmac_sha384:
            digest = new CK::SHA384;
            break;
        case hmac_sha512:
            digest = new CK::SHA512;
            break;
        default:
            throw RecordException("Invalid HMAC algorithm");
    }

    ConnectionEnd end = state->getEntity();
    coder::ByteArray seed(end == server ? "server finished" : "client finished");
    coder::ByteArray hash(digest->digest(finished));
    seed.append(hash);

    digest->reset();
    CK::HMAC hmac(digest);
    uint32_t keyLength = state->getMacKeyLength();
    coder::ByteArray key(state->getMasterSecret());
    hmac.setKey(key.range(0, keyLength));
    hmac.setMessage(seed);

    encoded.append(hmac.getHMAC());

    return encoded;

}

void Finished::initState(const coder::ByteArray& f) {

    finished = f;

}

}

