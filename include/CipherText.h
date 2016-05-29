#ifndef CIPHERTEXT_H_INCLUDED
#define CIPHERTEXT_H_INCLUDED

#include "RecordProtocol.h"

namespace CK {
    class Cipher;
}

namespace CKTLS {

class CipherText : public RecordProtocol {

    public:
        CipherText();
        ~CipherText();

    private:
        CipherText(const CipherText& other);
        CipherText& operator= (const CipherText& other);

    public:
        const coder::ByteArray& getPlaintext() const;
        void setAlgorithm(BulkCipherAlgorithm alg);
        void setCipherType(CipherType cipher);
        void setIV(const coder::ByteArray& iv);
        void setKey(const coder::ByteArray& key);
        void setKeyLength(uint32_t keylength);
        void setPlaintext(const coder::ByteArray& plain);
        void setSequenceNumber(uint64_t seq);

    protected:
        void encode();
        void decode();

    private:
        void decryptGCM(const coder::ByteArray& ciphertext,
                            CK::Cipher *cipher, const coder::ByteArray& tag);
        void encryptGCM(CK::Cipher *cipher);

    private:
        BulkCipherAlgorithm algorithm;
        CipherType type;
        uint32_t keyLength;
        uint64_t sequence;
        coder::ByteArray key;
        coder::ByteArray iv;
        coder::ByteArray plaintext;

};

}

#endif  // CIPHERTEXT_H_INCLUDED
