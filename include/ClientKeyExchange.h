#ifndef CLIENTKEYEXCHANGE_H_INCLUDED
#define CLIENTKEYEXCHANGE_H_INCLUDED

#include "HandshakeBody.h"
#include "Constants.h"
#include "keys/ECDHKeyExchange.h"
#include "data/BigInteger.h"

namespace CK {
    class RSAPrivateKey;
}

namespace CKTLS {

class ClientKeyExchange : public HandshakeBody {

    public:
        ClientKeyExchange();
        ~ClientKeyExchange();

    private:
        ClientKeyExchange(const ClientKeyExchange& other);
        ClientKeyExchange& operator= (const ClientKeyExchange& other);

    public:
        const coder::ByteArray& encode();
        const CK::BigInteger& getDHPublicKey() const;
        const coder::ByteArray& getECPublicKey() const;
        void initState() {}
        void initState(NamedCurve curve, const coder::ByteArray& pk);
        void initState(const CK::ECDHKeyExchange::CurveParams& p,
                                                const coder::ByteArray& pk);
        void initState(const CK::BigInteger& pk);
        static void setAlgorithm(KeyExchangeAlgorithm alg);

    protected:
        void decode();

    private:
        void decodeDH(const coder::ByteArray& encoded);
        void decodeECDH(const coder::ByteArray& encoded);
        coder::ByteArray encodeDH() const;
        coder::ByteArray encodeECDH() const;

    private:
        static KeyExchangeAlgorithm algorithm;
        // ClientDHParams
        CK::BigInteger dYc;     // D-H public value.
        // EC parameters
        ECCurveType curveType;
        struct ECCurve {
            CK::BigInteger a;
            CK::BigInteger b;
        };
        // Explicit prime curve type
        CK::BigInteger primeP;
        ECCurve curve;
        CK::BigInteger baseX;
        CK::BigInteger baseY;
        CK::BigInteger order;
        uint32_t cofactor;
        // Explicit characteristic 2
        uint16_t m;
        ECBasisType ebType;
        // EC trinomial
        coder::ByteArray k;
        // EC Pentanomial
        coder::ByteArray k1;
        coder::ByteArray k2;
        coder::ByteArray k3;

        // Named curves
        NamedCurve named;
        
        // Key exchange
        coder::ByteArray ecPublicKey;

};

}

#endif  // CLIENTKEYEXCHANGE_H_INCLUDED
