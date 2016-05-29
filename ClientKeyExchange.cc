#include "tls/ClientKeyExchange.h"
#include "coder/Unsigned16.h"
#include "tls/exceptions/RecordException.h"
#include "tls/exceptions/EncodingException.h"

namespace CKTLS {

// Static initialization.
KeyExchangeAlgorithm ClientKeyExchange::algorithm;

ClientKeyExchange::ClientKeyExchange() {
}

ClientKeyExchange::~ClientKeyExchange() {
}

void ClientKeyExchange::decode() {

    switch (algorithm) {
        case dhe_rsa:
            decodeDH(encoded);
            break;
        case ec_diffie_hellman:
            decodeECDH(encoded);
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

}

void ClientKeyExchange::decodeDH(const coder::ByteArray& encoded) {

        coder::Unsigned16 len(encoded.range(0, 2), coder::bigendian);
        dYc.decode(encoded.range(2, len.getValue()), CK::BigInteger::BIGENDIAN);

}

void ClientKeyExchange::decodeECDH(const coder::ByteArray& encoded) {
}

const coder::ByteArray& ClientKeyExchange::encode() {

    switch (algorithm) {
        case dhe_rsa:
            encoded.append(encodeDH());
            break;
        case ec_diffie_hellman:
            encoded.append(encodeECDH());
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

    return encoded;

}

coder::ByteArray ClientKeyExchange::encodeDH() const {

    coder::ByteArray encoded;

    coder::ByteArray pk(dYc.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::Unsigned16 len(pk.getLength());
    encoded.append(len.getEncoded(coder::bigendian));
    encoded.append(pk);

    return encoded;

}

coder::ByteArray ClientKeyExchange::encodeECDH() const {

    coder::ByteArray encoded;

    return encoded;

}

const CK::BigInteger& ClientKeyExchange::getDHPublicKey() const {

    return dYc;

}

const coder::ByteArray& ClientKeyExchange::getECPublicKey() const {

    return ecPublicKey;

}

void ClientKeyExchange::initState(const CK::BigInteger& pk) {

    dYc = pk;

}

void ClientKeyExchange::initState(NamedCurve curve, const coder::ByteArray& pk) {

    algorithm = ec_diffie_hellman;
    curveType = named_curve;
    named = curve;
    ecPublicKey = pk;

}

void ClientKeyExchange::initState(const CK::ECDHKeyExchange::CurveParams& params,
                                                    const coder::ByteArray& pk) {

    algorithm = ec_diffie_hellman;
    curveType = explicit_prime;

    primeP = params.p;
    curve.a = params.a;
    curve.b = params.b;
    order = params.n;
    cofactor = params.h;
    baseX = params.xG;
    baseY = params.yG;

    ecPublicKey = pk;

}

void ClientKeyExchange::setAlgorithm(KeyExchangeAlgorithm alg) {

    algorithm = alg;

}

}
