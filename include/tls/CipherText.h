#ifndef CIPHERTEXT_H_INCLUDED
#define CIPHERTEXT_H_INCLUDED

#include "RecordProtocol.h"

namespace CK {
    class Cipher;
}

namespace CKTLS {

#ifndef _TLS_THREAD_LOCAL_
class StateContainer;
#endif

class CipherText : public RecordProtocol {

    public:
#ifdef _TLS_THREAD_LOCAL_
        CipherText();
#else
        CipherText(StateContainer *holder);
#endif
        ~CipherText();

    private:
        CipherText(const CipherText& other);
        CipherText& operator= (const CipherText& other);

    public:
        const coder::ByteArray& getPlaintext() const { return plaintext; }
        //void setAlgorithm(BulkCipherAlgorithm alg);
        //void setCipherType(CipherType cipher);
        //void setIV(const coder::ByteArray& iv);
        //void setKey(const coder::ByteArray& key);
        //void setKeyLength(uint32_t keylength);
        void setPlaintext(const coder::ByteArray& plain) { plaintext = plain; }
        //void setSequenceNumber(uint64_t seq);

    protected:
        void encode();
        void decode();

    private:
        void decryptGCM(CK::Cipher *cipher);
        void encryptGCM(CK::Cipher *cipher);

    private:
        //BulkCipherAlgorithm algorithm;
        //CipherType type;
        //uint32_t keyLength;
        //uint64_t sequence;
        //coder::ByteArray key;
        //coder::ByteArray iv;
        coder::ByteArray plaintext;
#ifndef _TLS_THREAD_LOCAL_
        StateContainer *holder;
#endif

};

}

#endif  // CIPHERTEXT_H_INCLUDED
