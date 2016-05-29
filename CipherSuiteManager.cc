#include "CipherSuiteManager.h"
#include "coder/Unsigned16.h"
#include "exceptions/RecordException.h"

namespace CKTLS {

// Static initialization.
CipherSuiteList CipherSuiteManager::preferred;

CipherSuiteManager::CipherSuiteManager() {

    initialize();

}

CipherSuiteManager::CipherSuiteManager(const CipherSuiteManager& other)
: suites(other.suites) {
}

CipherSuiteManager::~CipherSuiteManager() {
}

void CipherSuiteManager::initialize() {

    if (preferred.size() == 0) {
        preferred.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        preferred.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        preferred.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
        preferred.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);
        preferred.push_back(TLS_NULL_WITH_NULL_NULL);
    }


}

#ifdef _DEBUG
void CipherSuiteManager::debugOut(std::ostream& out) const {

    for (CipherConstIter it = suites.begin(); it != suites.end(); ++it) {
        coder::Unsigned16 cs(*it);
        coder::ByteArray csb(cs.getEncoded(coder::bigendian));
        out << "Cipher suite: 0x";
        for (int i = 0; i < 2; ++i) {
            char c = (csb[i] >> 4) & 0x0f;
            if (c < 0x0a) {
                c = c + '0';
            }
            else {
                c = (c - 0x0a) + 'a';
            }
            out << c;
            c = csb[i] & 0x0f;
            if (c < 0x0a) {
                c = c + '0';
            }
            else {
                c = (c - 0x0a) + 'a';
            }
            out << c;
        }
        out << std::endl;
    }

}
#endif

void CipherSuiteManager::decode(const coder::ByteArray& encoded) {

    unsigned index = 0;
    while (index < encoded.getLength()) {
        coder::Unsigned16 c(encoded.range(index, 2), coder::bigendian);
        index += 2;
        suites.push_back(c.getValue());
    }

}

coder::ByteArray CipherSuiteManager::encode() const {

    coder::ByteArray encoded;
    for (CipherConstIter it = suites.begin();
                                    it != suites.end(); ++it) {
        coder::Unsigned16 c(*it);
        encoded.append(c.getEncoded(coder::bigendian));
    }

    return encoded;

}

CipherSuite CipherSuiteManager::getServerSuite() const {

    return suites.front();

}

bool CipherSuiteManager::isCurve(CipherSuite c) const {

    switch (c) {
        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
         return true;
    }

    return false;
}

void CipherSuiteManager::loadPreferred() {

    suites.push_back(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    suites.push_back(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    suites.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
    suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);

}

CipherSuite CipherSuiteManager::matchCipherSuite() const {

    for (CipherConstIter pit = preferred.begin(); pit != preferred.end(); ++pit) {
        for (CipherConstIter sit = suites.begin(); sit != suites.end(); ++sit) {
            if ((*pit) == (*sit)) {
                return *pit;
            }
        }
    }

    throw RecordException("No matching cipher suite");

}

void CipherSuiteManager::setPreferred(CipherSuite suite) {

    suites.push_back(suite);

}

}

