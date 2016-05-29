#include "ServerKeyExchange.h"
#include "ConnectionState.h"
#include "ServerCertificate.h"
#include "cipher/PKCS1rsassa.h"
#include "keys/RSAPrivateKey.h"
#include "coder/Unsigned16.h"
#include "coder/Unsigned32.h"
#include "digest/SHA256.h"
#include "digest/SHA384.h"
#include "digest/SHA512.h"
#include "exceptions/RecordException.h"
#include "exceptions/EncodingException.h"

namespace CKTLS {

// Static initialization.
KeyExchangeAlgorithm ServerKeyExchange::algorithm;

ServerKeyExchange::ServerKeyExchange() {

    rsaKey = ServerCertificate::getRSAPrivateKey();

}

ServerKeyExchange::~ServerKeyExchange() {
}

void ServerKeyExchange::decode() {

    clientRandom = ConnectionState::getPendingWrite()->getClientRandom();
    serverRandom = ConnectionState::getPendingWrite()->getServerRandom();

    switch (algorithm) {
        case dhe_rsa:
            decodeDH();
            break;
        case ec_diffie_hellman:
            decodeECDH();
            break;
        default:
            throw RecordException("Invalid key exchange algorithm");
    }

}

void ServerKeyExchange::decodeDH() {

    coder::ByteArray serverDHParams;

    uint32_t index = 0;
    serverDHParams.append(encoded.range(index, 2));
    coder::Unsigned16 len(encoded.range(index, 2), coder::bigendian);
    index += 2;
    uint16_t length = len.getValue();
    serverDHParams.append(encoded.range(index, length));
    dP.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
    //std::cout << "dP = " << dP << std::endl;
    index += length;

    serverDHParams.append(encoded.range(index, 2));
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    length = len.getValue();
    serverDHParams.append(encoded.range(index, length));
    dG.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
    //std::cout << "dG = " << dG << std::endl;
    index += length;

    serverDHParams.append(encoded.range(index, 2));
    len.decode(encoded.range(index, 2), coder::bigendian);
    index += 2;
    length = len.getValue();
    serverDHParams.append(encoded.range(index, length));
    dYs.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
    //std::cout << "dYs = " << dYs << std::endl;
    index += length;

    //std::cout << "clientRandom = " << clientRandom << std::endl;
    coder::ByteArray hash(clientRandom);
    //std::cout << "serverRandom = " << serverRandom << std::endl;
    hash.append(serverRandom);
    //std::cout << "serverDHParams = " << serverDHParams << std::endl;
    hash.append(serverDHParams);

    HashAlgorithm ha = static_cast<HashAlgorithm>(encoded[index++]);
    CK::Digest *digest;
    switch (ha) {
        case sha256:
            digest = new CK::SHA256;
            break;
        case sha384:
            digest = new CK::SHA384;
            break;
        case sha512:
            digest = new CK::SHA512;
            break;
        default:
            throw EncodingException(std::string("ServerKeyExchange decodeDH: ")
                            + std::string("Unsupported signature hash algorithm"));
    }

    SignatureAlgorithm sa = static_cast<SignatureAlgorithm>(encoded[index++]);
    coder::Unsigned16 siglen(encoded.range(index, 2), coder::bigendian);
    index += 2;
    coder::ByteArray sig(encoded.range(index, siglen.getValue()));

    switch (sa) {
        case rsa:
            {
            CK::PKCS1rsassa sign(digest);
            CK::RSAPublicKey *pubKey = ServerCertificate::getRSAPublicKey();
            if (!sign.verify(*pubKey, hash, sig)) {
                dYs = CK::BigInteger::ZERO;
                throw EncodingException("ServerKeyExchange decodeDH: Key not verified");
            }
            }
            break;
        default:
            throw EncodingException("ServerKeyExchange decodeDH: Unsupported signature algorithm");
    }

}

void ServerKeyExchange::decodeECDH() {

    curveType = static_cast<ECCurveType>(encoded[0]);
    uint32_t index = 1;
    uint8_t length;
    uint32_t paramsLength = 1;
    switch (curveType) {
        case explicit_prime:
            {
            // Prime
            length = encoded[index++];
            paramsLength += length + 1;
            primeP.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            // ECCurve
            length = encoded[index++];
            paramsLength += length + 1;
            curve.a.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            length = encoded[index++];
            paramsLength += length + 1;
            curve.b.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            // Base
            length = encoded[index++] - 1;
            paramsLength += length + 2;
            if (encoded[index++] != 0x04) {
                throw EncodingException("Invalid base point format");
            }
            baseX.decode(encoded.range(index, length / 2), CK::BigInteger::BIGENDIAN);
            index += (length / 2);
            baseY.decode(encoded.range(index, length / 2), CK::BigInteger::BIGENDIAN);
            index += (length / 2);
            // Order
            length = encoded[index++];
            paramsLength += length + 1;
            order.decode(encoded.range(index, length), CK::BigInteger::BIGENDIAN);
            index += length;
            // Cofactor
            length = encoded[index++];
            paramsLength += length + 1;
            if (length != 4) {
                throw EncodingException("Invalid cofactor length");
            }
            coder::Unsigned32 co(encoded.range(index, 4), coder::bigendian);
            cofactor = co.getValue();
            }
            break;
        case named_curve:
            {
            length = encoded[index++];
            paramsLength += length + 1;
            if (length != 2) {
                throw EncodingException("Invalid named curve length");
            }
            coder::Unsigned16 nc(encoded.range(index, 2), coder::bigendian);
            index += 2;
            named = static_cast<NamedCurve>(nc.getValue());
            switch (named) {
                case secp256r1:
                    order = CK::ECDHKeyExchange::SECP256R1.n;
                    curve.a = CK::ECDHKeyExchange::SECP256R1.a;
                    curve.b = CK::ECDHKeyExchange::SECP256R1.b;
                    baseX = CK::ECDHKeyExchange::SECP256R1.xG;
                    baseY = CK::ECDHKeyExchange::SECP256R1.yG;
                    primeP = CK::ECDHKeyExchange::SECP256R1.p;
                    cofactor = CK::ECDHKeyExchange::SECP256R1.h;
                    break;
                case secp384r1:
                    order = CK::ECDHKeyExchange::SECP384R1.n;
                    curve.a = CK::ECDHKeyExchange::SECP384R1.a;
                    curve.b = CK::ECDHKeyExchange::SECP384R1.b;
                    baseX = CK::ECDHKeyExchange::SECP384R1.xG;
                    baseY = CK::ECDHKeyExchange::SECP384R1.yG;
                    primeP = CK::ECDHKeyExchange::SECP384R1.p;
                    cofactor = CK::ECDHKeyExchange::SECP384R1.h;
                    break;
                case secp256k1:
                    order = CK::ECDHKeyExchange::SECP256K1.n;
                    curve.a = CK::ECDHKeyExchange::SECP256K1.a;
                    curve.b = CK::ECDHKeyExchange::SECP256K1.b;
                    baseX = CK::ECDHKeyExchange::SECP256K1.xG;
                    baseY = CK::ECDHKeyExchange::SECP256K1.yG;
                    primeP = CK::ECDHKeyExchange::SECP256K1.p;
                    cofactor = CK::ECDHKeyExchange::SECP256K1.h;
                    break;
                default:
                    throw EncodingException("Invalid named curve");
            }
            }
            break;
        default:
            throw EncodingException("Invalid curve type");
    }

    length = encoded[index++];
    ecPublicKey.clear();
    ecPublicKey.append(encoded.range(index, length));
    index += length;
    coder::ByteArray serverECDH(encoded.range(0, paramsLength));
    serverECDH.append(length);
    serverECDH.append(ecPublicKey);

    coder::ByteArray hash(clientRandom);
    hash.append(serverRandom);
    hash.append(serverECDH);

    HashAlgorithm ha = static_cast<HashAlgorithm>(encoded[index++]);
    CK::Digest *digest;
    switch (ha) {
        case sha256:
            digest = new CK::SHA256;
            break;
        case sha384:
            digest = new CK::SHA384;
            break;
        case sha512:
            digest = new CK::SHA512;
            break;
        default:
            throw EncodingException("Unsupported signature hash algorithm");
    }

    SignatureAlgorithm sa = static_cast<SignatureAlgorithm>(encoded[index++]);
    coder::Unsigned16 siglen(encoded.range(index, 2), coder::bigendian);
    index += 2;
    coder::ByteArray sig(encoded.range(index, siglen.getValue()));

    switch (sa) {
        case rsa:
            {
            CK::PKCS1rsassa sign(digest);
            CK::RSAPublicKey *pubKey = ServerCertificate::getRSAPublicKey();
            if (!sign.verify(*pubKey, hash, sig)) {
                ecPublicKey.clear();
                throw EncodingException("ServerKeyExchange decodeECDH: Key not verified");
            }
            }
            break;
        default:
            throw EncodingException("ServerKeyExchange decodeECDH: Unsupported signature algorithm");
    }

}

const coder::ByteArray& ServerKeyExchange::encode() {

    clientRandom = ConnectionState::getPendingRead()->getClientRandom();
    serverRandom = ConnectionState::getPendingRead()->getServerRandom();

    switch (algorithm) {
        case dhe_rsa:
            encodeDH();
            break;
        case ec_diffie_hellman:
            encodeECDH();
            break;
        default:
            throw RecordException("ServerKeyExchange encode: Invalid key exchange algorithm");
    }

    return encoded;

}

void ServerKeyExchange::encodeDH() {

    coder::ByteArray serverDHParams;
    //std::cout << "dP = " << dP << std::endl;
    coder::ByteArray p(dP.getEncoded(CK::BigInteger::BIGENDIAN));
    coder::Unsigned16 len(p.getLength());
    serverDHParams.append(len.getEncoded(coder::bigendian));
    serverDHParams.append(p);
    //std::cout << "dG = " << dG << std::endl;
    coder::ByteArray g(dG.getEncoded(CK::BigInteger::BIGENDIAN));
    len.setValue(g.getLength());
    serverDHParams.append(len.getEncoded(coder::bigendian));
    serverDHParams.append(g);
    //std::cout << "dYs = " << dYs << std::endl;
    coder::ByteArray pk(dYs.getEncoded(CK::BigInteger::BIGENDIAN));
    len.setValue(pk.getLength());
    serverDHParams.append(len.getEncoded(coder::bigendian));
    serverDHParams.append(pk);
    encoded.append(serverDHParams);

    //std::cout << "clientRandom = " << clientRandom << std::endl;
    coder::ByteArray hash(clientRandom);
    //std::cout << "serverRandom = " << serverRandom << std::endl;
    hash.append(serverRandom);
    //std::cout << "serverDHParams = " << serverDHParams << std::endl;
    hash.append(serverDHParams);

    CK::PKCS1rsassa sign(new CK::SHA256);
    coder::ByteArray sig(sign.sign(*rsaKey, hash));


    coder::Unsigned16 siglen(sig.getLength());
    encoded.append(sha256);
    encoded.append(rsa);
    encoded.append(siglen.getEncoded(coder::bigendian));
    encoded.append(sig);

}

void ServerKeyExchange::encodeECDH() {

    coder::ByteArray params;   // ECParameters
    params.append(curveType);
    switch (curveType) {
        case explicit_prime:
            {
            // Prime
            coder::ByteArray p(primeP.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(p.getLength());
            params.append(p);
            // ECCurve
            coder::ByteArray a(curve.a.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(a.getLength());
            params.append(a);
            coder::ByteArray b(curve.b.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(b.getLength());
            params.append(b);
            // Base
            coder::ByteArray point(1, 0x04);
            point.append(baseX.getEncoded(CK::BigInteger::BIGENDIAN));
            point.append(baseY.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(point.getLength());
            params.append(point);
            // Order
            coder::ByteArray o(order.getEncoded(CK::BigInteger::BIGENDIAN));
            params.append(o.getLength());
            params.append(o);
            // Cofactor
            coder::Unsigned32 co(cofactor);
            params.append(4);
            params.append(co.getEncoded(coder::bigendian));
            }
            break;
        case named_curve:
            {
            params.append(2);
            coder::Unsigned16 nc(named);
            params.append(nc.getEncoded(coder::bigendian));
            }
            break;
        default:
            throw RecordException("Invalid curve type");
    }

    coder::ByteArray pk(ecPublicKey);
    coder::ByteArray serverECDH(params);
    serverECDH.append(pk.getLength());
    serverECDH.append(pk);
    encoded.append(serverECDH);

    coder::ByteArray hash(clientRandom);
    hash.append(serverRandom);
    hash.append(serverECDH);

    CK::PKCS1rsassa sign(new CK::SHA256);
    coder::ByteArray sig(sign.sign(*rsaKey, hash));


    coder::Unsigned16 siglen(sig.getLength());
    encoded.append(sha256);
    encoded.append(rsa);
    encoded.append(siglen.getEncoded(coder::bigendian));
    encoded.append(sig);

}

CK::ECDHKeyExchange::CurveParams ServerKeyExchange::getCurve() const {

    CK::ECDHKeyExchange::CurveParams params;
    params.m = 0;
    params.n = order;
    params.a = curve.a;
    params.b = curve.b;
    params.xG = baseX;
    params.yG = baseY;
    params.p - primeP;
    params.h = cofactor;

    return params;

}

const CK::BigInteger& ServerKeyExchange::getDHGenerator() const {

    return dG;

}

const CK::BigInteger& ServerKeyExchange::getDHModulus() const {

    return dP;

}

const CK::BigInteger& ServerKeyExchange::getDHPublicKey() const {

    return dYs;

}

const coder::ByteArray& ServerKeyExchange::getECPublicKey() const {

    return ecPublicKey;

}

void ServerKeyExchange::initState(const CK::BigInteger& g, const CK::BigInteger& p,
                                                    const CK::BigInteger& pk) {

    dP = p;
    dG = g;
    dYs = pk;

}

void ServerKeyExchange::initState(NamedCurve curve, const coder::ByteArray& pk) {

    algorithm = ec_diffie_hellman;
    curveType = named_curve;
    named = curve;
    ecPublicKey = pk;

}

void ServerKeyExchange::initState(const CK::ECDHKeyExchange::CurveParams& params,
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

void ServerKeyExchange::setAlgorithm(KeyExchangeAlgorithm alg) {

    algorithm = alg;

}

}
