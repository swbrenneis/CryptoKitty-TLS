#include "tls/ServerCertificate.h"
#include "tls/exceptions/RecordException.h"
#include "coder/Unsigned64.h"
#include "coder/Unsigned16.h"

namespace CKTLS {

//Static initialization.
CK::RSAPrivateKey *ServerCertificate::rsaPrivateKey = 0;
CK::RSAPublicKey *ServerCertificate::rsaPublicKey = 0;

ServerCertificate::ServerCertificate()
: cert(0),
  keyID(0),
  type(empty_cert) {
}

ServerCertificate::~ServerCertificate() {
}

#ifdef _DEBUG
void ServerCertificate::debugOut(std::ostream& out) {

    out << "certificate" << std::endl;
    out << "Type: ";
    switch (type) {
        case empty_cert:
            out << "Empty certificate.";
            break;
        case subkey_cert:
            out << "Sub-key certificate.";
            break;
        case subkey_cert_fingerprint:
            out << "Sub-key certificate fingerprint.";
            break;
    }
    out << std::endl;
    out << "Key ID: " << keyID << std::endl;
    out << "Certificate: " << std::endl;

}
#endif

void ServerCertificate::decode() {

    type = static_cast<OpenPGPCertDescriptorType>(encoded[0]);
    if (type != subkey_cert) {
        throw RecordException("Invalid certificate type");
    }

    uint8_t keySize = encoded[1];
    coder::Unsigned64 id(encoded.range(2, keySize), coder::bigendian);
    keyID = id.getValue();
    delete cert;
    uint32_t index = keySize + 2;
    coder::Unsigned16 len(encoded.range(index, 2), coder::bigendian);
    index += 2;
    cert = new PGPCertificate(encoded.range(index, len.getValue()));
    rsaPublicKey = cert->getPublicKey()->getRSAPublicKey();

}

const coder::ByteArray& ServerCertificate::encode() {

    encoded.append(type);
    coder::Unsigned64 id(keyID);
    encoded.append(8);
    encoded.append(id.getEncoded(coder::bigendian));
    coder::ByteArray pgp(cert->encode());
    coder::Unsigned16 len(pgp.getLength());
    encoded.append(len.getEncoded(coder::bigendian));
    encoded.append(pgp);

    return encoded;

}

CK::RSAPrivateKey *ServerCertificate::getRSAPrivateKey() {

    return rsaPrivateKey;

};

CK::RSAPublicKey *ServerCertificate::getRSAPublicKey() {

    return rsaPublicKey;

};

void ServerCertificate::initState() {

     type = subkey_cert;

}

void ServerCertificate::setCertificate(PGPCertificate *c) {

    cert = c;
    rsaPublicKey = cert->getPublicKey()->getRSAPublicKey();

}

void ServerCertificate::setKeyID(uint64_t id) {

    keyID = id;

}

void ServerCertificate::setRSAPrivateKey(CK::RSAPrivateKey *pk) {

    rsaPrivateKey = pk;

}

}

