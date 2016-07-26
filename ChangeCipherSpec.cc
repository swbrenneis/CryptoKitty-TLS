#include "tls/ChangeCipherSpec.h"
#include "tls/ConnectionState.h"
#include "tls/exceptions/EncodingException.h"
#include "tls/exceptions/RecordException.h"
#include <CryptoKitty-C/cipher/AES.h>
#include <CryptoKitty-C/ciphermodes/GCM.h>
#include <coder/Unsigned64.h>

namespace CKTLS {

// Static initialization
const uint8_t ChangeCipherSpec::MAJORVERSION = 3;
const uint8_t ChangeCipherSpec::MINORVERSION = 3;

#ifdef _TLS_THREAD_LOCAL_
ChangeCipherSpec::ChangeCipherSpec()
: RecordProtocol(change_cipher_spec) {
}
#else
ChangeCipherSpec::ChangeCipherSpec(StateContainer *h)
: RecordProtocol(change_cipher_spec),
  holder(h) {
}
#endif
ChangeCipherSpec::~ChangeCipherSpec() {
}

/*
 * Decode the message. Assumes that the preamble has been stripped off.
 */
void ChangeCipherSpec::decode() {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getPendingRead();
#else
    ConnectionState *state = holder->getPendingRead();
#endif

    switch(state->getCipherType()) {
        case stream:
            // TODO
            break;
        case block:
            // TODO
            break;
        case aead:
            {
            CK::Cipher *cipher = getCipher(state);
            const coder::ByteArray& iv(state->getIV());
            CK::GCM gcm(cipher, iv);
            const coder::ByteArray& key(state->getEncryptionKey());
            coder::Unsigned64 seq(state->getSequenceNumber());
            coder::ByteArray ad(seq.getEncoded(coder::bigendian));
            ad.append(0);   // Compression type.
            ad.append(MAJORVERSION);   // Major version.
            ad.append(MINORVERSION);   // Minor version.
            ad.append(1);   // Data length.
            gcm.setAuthData(ad);
            if (fragment.getLength() != 17) {
                throw EncodingException("Invalid ciphertext");
            }
            coder::ByteArray plaintext(gcm.decrypt(fragment.range(0, 1), key));
            if (plaintext.getLength() != 1 || plaintext[0] != 1) {
                throw EncodingException("Invalid plaintext");
            }
            }
            break;
    }

}

void ChangeCipherSpec::encode() {

#ifdef _TLS_THREAD_LOCAL_
    ConnectionState *state = ConnectionState::getPendingWrite();
#else
    ConnectionState *state = holder->getPendingWrite();
#endif

    coder::ByteArray plaintext(1, 1);

    switch(state->getCipherType()) {
        case stream:
            // TODO
            break;
        case block:
            // TODO
            break;
        case aead:
            {
            CK::Cipher *cipher = getCipher(state);
            const coder::ByteArray& iv(state->getIV());
            CK::GCM gcm(cipher, iv);
            const coder::ByteArray& key(state->getEncryptionKey());
            coder::Unsigned64 seq(state->getSequenceNumber());
            coder::ByteArray ad(seq.getEncoded(coder::bigendian));
            ad.append(0);   // Compression type.
            ad.append(MAJORVERSION);   // Major version.
            ad.append(MINORVERSION);   // Minor version.
            ad.append(1);   // Data length.
            gcm.setAuthData(ad);
            coder::ByteArray ciphertext(gcm.encrypt(plaintext, key));
            // We're using the default authentication tag length of 128 bits.
            if (ciphertext.getLength() != 17) {
                throw RecordException("Invalid ciphertext");
            }
            fragment.append(ciphertext);
            }
            break;
    }

}

CK::Cipher *ChangeCipherSpec::getCipher(ConnectionState *state) const {

    uint32_t keySize = state->getEncryptionKeyLength();

    CK::Cipher *cipher = 0;
    switch(state->getCipherAlgorithm()) {
        case rc4:
            // TODO
            break;
        case tdes:
            // TODO
            break;
        case aes:
            switch (keySize) {
                case 128:
                    cipher = new CK::AES(CK::AES::AES128);
                    break;
                case 256:
                    cipher = new CK::AES(CK::AES::AES256);
                    break;
                default:
                    throw RecordException("Invalid AES key size");
            }
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    return cipher;

}

}

