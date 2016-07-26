#include "tls/CipherText.h"
#include "tls/ConnectionState.h"
#include "tls/exceptions/RecordException.h"
#include <coder/Unsigned16.h>
#include <coder/Unsigned64.h>
#include <CryptoKitty-C/cipher/AES.h>
#include <CryptoKitty-C/ciphermodes/GCM.h>

namespace CKTLS {

static const uint32_t AEAD_TAGLENGTH = 16;

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
    coder::Unsigned64 u64(state->getSequenceNumber());
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    coder::Unsigned16 u16(fragment.getLength() - AEAD_TAGLENGTH);
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

}

