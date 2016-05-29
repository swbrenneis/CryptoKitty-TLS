#include "tls/ClientHello.h"
#include "tls/ExtensionManager.h"
#include "coder/Unsigned32.h"
#include "random/FortunaSecureRandom.h"
#include "exceptions/OutOfRangeException.h"
#include "tls/exceptions/RecordException.h"
#include <time.h>

namespace CKTLS {

static const uint8_t MAJOR = 3;
static const uint8_t MINOR = 3;

ClientHello::ClientHello()
: random(28, 0),
  sessionID(0),
  majorVersion(MAJOR),
  minorVersion(MINOR) {
}

ClientHello::ClientHello(const ClientHello& other) 
: gmt(other.gmt),
  random(other.random),
  sessionID(other.sessionID),
  majorVersion(other.majorVersion),
  minorVersion(other.minorVersion),
  compressionMethods(other.compressionMethods),
  suites(other.suites),
  extensions(other.extensions) {
}

ClientHello::~ClientHello() {
}

#ifdef _DEBUG
void ClientHello::debugOut(std::ostream& out) {

    out << "client_hello" << std::endl;
    int j = majorVersion;
    int n = minorVersion;
    out << "Version: " << j << "." << n << std::endl;
    out << "Random.gmt: " << gmt << std::endl;
    out << "Random.random: " << random.toString() << std::endl;
    out << "Session ID: " << sessionID.toString() << std::endl;
    suites.debugOut(out);
    out << "Compression methods: " << compressionMethods.toString() << std::endl;
    extensions.debugOut(out);

}
#endif

void ClientHello::decode() {

    unsigned index = 0;
    // Protocol version
    majorVersion = encoded[index++];
    minorVersion = encoded[index++];
    // Random
    coder::Unsigned32 g(encoded.range(index, 4), coder::bigendian);
    gmt = g.getValue();
    index += 4;
    random = encoded.range(index, 28);
    index += 28;
    // Session ID
    uint8_t sidLen = encoded[index++];
    if (sidLen > 0) {
        sessionID = encoded.range(index, sidLen);
        index += sidLen;
    }
    // Cipher suites
    coder::Unsigned16 csl(encoded.range(index, 2), coder::bigendian);
    uint16_t csLen = csl.getValue();
    suites.decode(encoded.range(index+2, csLen));
    index += csLen + 2;
    // Compression methods
    uint8_t compMethods = encoded[index++];
    while (compMethods > 0) {
        compressionMethods.append(encoded[index++]);
        compMethods--;
    }
    // Extensions. Be very, very careful. Uses ByteArray bounds
    // check to validate lengths.
    try {
        if (index < encoded.getLength() - 1) {
            coder::Unsigned16 exl(encoded.range(index, 2), coder::bigendian);
            uint16_t exLength = exl.getValue();
            index += 2;
            extensions.decode(encoded.range(index, exLength));
            index += exLength;
        }

    }
    catch (CK::OutOfRangeException& ee) {
        throw RecordException("Extensions decode overrun");
    }

    if (index != encoded.getLength()) {
        throw RecordException("Decoding underrun");
    }

}

const coder::ByteArray& ClientHello::encode() {

    encoded.append(majorVersion);
    encoded.append(minorVersion);

    coder::Unsigned32 g(gmt);
    encoded.append(g.getEncoded(coder::bigendian));
    encoded.append(random);

    uint8_t slen = sessionID.getLength();
    encoded.append(slen);
    if (slen > 0) {
        encoded.append(sessionID);
    }

    coder::ByteArray s(suites.encode());
    coder::Unsigned16 suiteLen(s.getLength());
    encoded.append(suiteLen.getEncoded(coder::bigendian));
    encoded.append(s);

    encoded.append(compressionMethods.getLength());
    for (unsigned i = 0; i < compressionMethods.getLength(); ++i) {
        encoded.append(compressionMethods[i]);
    }

    encoded.append(extensions.encode());

    return encoded;

}

bool ClientHello::getExtension(uint16_t eType, Extension& ext) const {

    ext = extensions.getExtension(eType);
    return ext.type.getValue() == eType;

}

uint8_t ClientHello::getMajorVersion() const {

    return majorVersion;

}

uint8_t ClientHello::getMinorVersion() const {

    return minorVersion;

}

CipherSuite ClientHello::getPreferred() const {

    return suites.matchCipherSuite();

}

const coder::ByteArray& ClientHello::getRandom() const {

    return random;

}

void ClientHello::initState() {

    gmt = time(0);
    CK::FortunaSecureRandom rnd;
    rnd.nextBytes(random);
    suites.loadPreferred();
    compressionMethods.append(0);
    extensions.loadDefaults();

}

}
