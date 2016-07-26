#include "tls/CipherText.h"
#include "tls/ConnectionState.h"
#include "tls/exceptions/RecordException.h"
#include <coder/Unsigned16.h>
#include <coder/Unsigned64.h>
#include <CryptoKitty-C/cipher/AES.h>
#include <CryptoKitty-C/ciphermodes/GCM.h>

namespace CKTLS {

#ifdef _TLS_THREAD_LOCAL_
CipherText::CipherText()
: RecordProtocol(application_data) {
}
#else
CipherText::CipherText(StateContainer *h)
: RecordProtocol(application_data),
  holder(h) {
}
#endif

CipherText::~CipherText() {
}

void CipherText::decode() {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getCurrentWrite();
#else
    ConnectionState *state = holder->getCurrentWrite();
#endif

    CK::Cipher *cipher;
    uint32_t keyLength = state->getEncryptionKeyLength() / 8;
    switch (state->getCipherAlgorithm()) {
        case aes:
            cipher = new CK::AES(static_cast<CK::AES::KeySize>(keyLength));
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    switch (state->getCipherType()) {
        case aead:
            decryptGCM(cipher);
            break;
        default:
            throw RecordException("Invalid cipher mode");
    }

}

void CipherText::decryptGCM(CK::Cipher *cipher) {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getCurrentWrite();
#else
    ConnectionState *state = holder->getCurrentWrite();
#endif

    coder::ByteArray key(state->getEncryptionKey());
    coder::ByteArray iv(state->getIV());
    CK::GCM gcm(cipher, iv);

    coder::ByteArray ad;
    uint64_t sequence = state->getSequenceNumber();
    coder::Unsigned64 u64(sequence);
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    coder::Unsigned16 u16(fragment.getLength());
    ad.append(u16.getEncoded(coder::bigendian));

    gcm.setAuthData(ad);
    plaintext = gcm.decrypt(fragment, key);

}

void CipherText::encode() {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getCurrentRead();
#else
    ConnectionState *state = holder->getCurrentRead();
#endif

    fragment.clear();

    CK::Cipher *cipher;
    uint32_t keyLength = state->getEncryptionKeyLength() / 8;
    switch (state->getCipherAlgorithm()) {
        case aes:
            cipher = new CK::AES(static_cast<CK::AES::KeySize>(keyLength));
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    switch (state->getCipherType()) {
        case aead:
            encryptGCM(cipher);
            break;
        default:
            throw RecordException("Invalid cipher mode");
    }

}

void CipherText::encryptGCM(CK::Cipher *cipher) {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getCurrentRead();
#else
    ConnectionState *state = holder->getCurrentRead();
#endif

    coder::ByteArray key(state->getEncryptionKey());
    coder::ByteArray iv(state->getIV());
    CK::GCM gcm(cipher, iv);

    coder::ByteArray ad;
    coder::Unsigned64 u64(state->getSequenceNumber());
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    coder::Unsigned16 u16(plaintext.getLength());
    ad.append(u16.getEncoded(coder::bigendian));

    gcm.setAuthData(ad);
    fragment.append(gcm.encrypt(plaintext, key));

}

/*const coder::ByteArray& CipherText::getPlaintext() const {

    return plaintext;

}

void CipherText::setAlgorithm(BulkCipherAlgorithm alg) {

    algorithm = alg;

}

void CipherText::setCipherType(CipherType cipher) {

    type = cipher;

}

void CipherText::setIV(const coder::ByteArray& i) {

    iv = i;

}

void CipherText::setKey(const coder::ByteArray& k) {

    key = k;

}

void CipherText::setKeyLength(uint32_t keylength) {

    keyLength = keylength / 8;

}

void CipherText::setPlaintext(const coder::ByteArray& plain) {

    plaintext = plain;

}

void CipherText::setSequenceNumber(uint64_t seq) {

    sequence = seq;

}*/

}

