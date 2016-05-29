#ifndef SERVERKEYEXCHANGE_H_INCLUDED
#define SERVERKEYEXCHANGE_H_INCLUDED

#include "HandshakeBody.h"
#include "Constants.h"
#include "keys/ECDHKeyExchange.h"

namespace CK {
    class RSAPrivateKey;
}

namespace CKTLS {

class ServerKeyExchange : public HandshakeBody {

    public:
        ServerKeyExchange();
        ~ServerKeyExchange();

    private:
        ServerKeyExchange(const ServerKeyExchange& other);
        ServerKeyExchange& operator= (const ServerKeyExchange& other);

    public:
        const coder::ByteArray& encode();
        CK::ECDHKeyExchange::CurveParams getCurve() const;
        const CK::BigInteger& getDHGenerator() const;
        const CK::BigInteger& getDHModulus() const;
        const CK::BigInteger& getDHPublicKey() const;
        const coder::ByteArray& getECPublicKey() const;
        void initState() {}
        void initState(NamedCurve curve, const coder::ByteArray& pk);
        void initState(const CK::ECDHKeyExchange::CurveParams& p,
                                                const coder::ByteArray& pk);
        void initState(const CK::BigInteger& g, const CK::BigInteger& p,
                                                const CK::BigInteger& pk);
        static void setAlgorithm(KeyExchangeAlgorithm alg);

    protected:
        void decode();

    private:
        void decodeDH();
        void decodeECDH();
        void encodeDH();
        void encodeECDH();

    private:
        static KeyExchangeAlgorithm algorithm;
        CK::RSAPrivateKey *rsaKey;
        // ServerDHParams
        CK::BigInteger dP;      // D-H prime modulus.
        CK::BigInteger dG;      // D-H generator.
        CK::BigInteger dYs;     // D-H public value.
        coder::ByteArray clientRandom;
        coder::ByteArray serverRandom;
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

#endif  // SERVERKEYEXCHANGE_H_INCLUDED
