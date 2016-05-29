#ifndef SERVERCERTIFICATE_H_INCLUDED
#define SERVERCERTIFICATE_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/PGPCertificate.h"

namespace CK {
    class RSAPrivateKey;
}

namespace CKTLS {

class ServerCertificate : public HandshakeBody {

    public:
        ServerCertificate();
        ~ServerCertificate();

    private:
        ServerCertificate(const ServerCertificate& other);
        ServerCertificate& operator= (const ServerCertificate& other);

    public:
        enum OpenPGPCertDescriptorType { empty_cert=1, subkey_cert=2,
                                            subkey_cert_fingerprint=3 };

    public:
#ifdef _DEBUG
        void debugOut(std::ostream& out);
#endif
        const coder::ByteArray& encode();
        static CK::RSAPrivateKey *getRSAPrivateKey();
        static CK::RSAPublicKey *getRSAPublicKey();
        void initState();
        void setKeyID(uint64_t id);
        void setCertificate(PGPCertificate *c);
        static void setRSAPrivateKey(CK::RSAPrivateKey *pk);

    protected:
        void decode();

    private:
        PGPCertificate *cert;
        uint64_t keyID;
        OpenPGPCertDescriptorType type;

        static CK::RSAPrivateKey *rsaPrivateKey;
        static CK::RSAPublicKey *rsaPublicKey;

};

}

#endif  // SERVERCERTIFICATE_H_INCLUDED
