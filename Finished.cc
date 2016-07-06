#include "tls/Finished.h"
#include "tls/ConnectionState.h"
#include "tls/exceptions/RecordException.h"
#include <CryptoKitty-C/mac/HMAC.h>
#include <CryptoKitty-C/digest/SHA256.h>
#include <CryptoKitty-C/digest/SHA384.h>
#include <CryptoKitty-C/digest/SHA512.h>

namespace CKTLS {

#ifdef _TLS_THREAD_LOCAL_
Finished::Finished() {
}
#else
Finished::Finished(StateContainer *h)
: holder(h) {
}
#endif

Finished::~Finished() {
}

bool Finished::authenticate(const coder::ByteArray& fin) const {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getCurrentRead();
#else
    ConnectionState *state = holder->getCurrentRead();
#endif
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

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getCurrentWrite();
#else
    ConnectionState *state = holder->getCurrentWrite();
#endif
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

