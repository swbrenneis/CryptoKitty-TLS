#include "tls/CipherText.h"
#include "tls/ConnectionState.h"
#include "coder/Unsigned16.h"
#include "coder/Unsigned64.h"
#include "cipher/AES.h"
#include "ciphermodes/GCM.h"
#include "tls/exceptions/RecordException.h"

namespace CKTLS {

CipherText::CipherText()
: RecordProtocol(application_data) {
}

CipherText::~CipherText() {
}

void CipherText::decode() {

    ConnectionState *state = ConnectionState::getCurrentWrite();

    uint8_t ivLength = fragment[0];
    iv = fragment.range(1, ivLength);
    coder::ByteArray stateIV(state->getIV());
    if (iv != stateIV) {
        throw RecordException("CipherText decode: IV not matched.");
    }
    sequence = state->getSequenceNumber();

    CK::Cipher *cipher;
    algorithm = state->getCipherAlgorithm();
    keyLength = state->getEncryptionKeyLength() / 8;
    key = state->getEncryptionKey();
    switch (algorithm) {
        case aes:
            cipher = new CK::AES(static_cast<CK::AES::KeySize>(keyLength));
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    type = state->getCipherType();
    switch (type) {
        case aead:
            {
            uint32_t ctLength = fragment.getLength() - ivLength - 1 - 16;
            coder::ByteArray ciphertext(fragment.range(ivLength + 1, ctLength));
            // Auth tag is always 16 bytes.
            coder::ByteArray tag(fragment.range(fragment.getLength() - 16, 16));
            decryptGCM(ciphertext, cipher, tag);
            }
            break;
        default:
            throw RecordException("Invalid cipher mode");
    }

}

void CipherText::decryptGCM(const coder::ByteArray& ciphertext,CK::Cipher *cipher,
                                                        const coder::ByteArray& tag) {

    CK::GCM gcm(cipher, iv);
    coder::ByteArray ad;
    coder::Unsigned64 u64(sequence);
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    // Full fragment size. Plaintext + tag size + iv size + 1.
    coder::Unsigned16 u16(fragment.getLength());
    ad.append(u16.getEncoded(coder::bigendian));
    //std::cout << "Decrypt AD = " << ad << std::endl;
    gcm.setAuthData(ad);
    //std::cout << "Decrypt tag = " << tag << std::endl;
    gcm.setAuthTag(tag);
    //std::cout << "Decrypt key = " << key << std::endl;
    plaintext = gcm.decrypt(ciphertext, key);

}

void CipherText::encode() {

    ConnectionState *state = ConnectionState::getCurrentRead();

    fragment.clear();

    iv = state->getIV();
    fragment.append(iv.getLength());
    fragment.append(iv);
    sequence = state->getSequenceNumber();

    CK::Cipher *cipher;
    algorithm = state->getCipherAlgorithm();
    keyLength = state->getEncryptionKeyLength() / 8;
    key = state->getEncryptionKey();
    switch (algorithm) {
        case aes:
            cipher = new CK::AES(static_cast<CK::AES::KeySize>(keyLength));
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    type = state->getCipherType();
    switch (type) {
        case aead:
            encryptGCM(cipher);
            break;
        default:
            throw RecordException("Invalid cipher mode");
    }

}

void CipherText::encryptGCM(CK::Cipher *cipher) {

    CK::GCM gcm(cipher, iv);
    coder::ByteArray ad;
    coder::Unsigned64 u64(sequence);
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    // Full fragment size. Plaintext + tag size + iv size + 1.
    coder::Unsigned16 u16(plaintext.getLength() + 16 + iv.getLength() + 1);
    ad.append(u16.getEncoded(coder::bigendian));
    //std::cout << "Encrypt AD = " << ad << std::endl;
    gcm.setAuthData(ad);
    //std::cout << "Encrypt key = " << key << std::endl;
    fragment.append(gcm.encrypt(plaintext, key));
    fragment.append(gcm.getAuthTag());
    //std::cout << "Encrypt tag = " << gcm.getAuthTag() << std::endl;

}

const coder::ByteArray& CipherText::getPlaintext() const {

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

}

}

