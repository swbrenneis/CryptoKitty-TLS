#ifndef CLIENTHELLO_H_INCLUDED
#define CLIENTHELLO_H_INCLUDED

#include "HandshakeBody.h"
#include "CipherSuiteManager.h"
#include "ExtensionManager.h"
#include <iostream>

namespace CKTLS {

class ClientHello : public HandshakeBody {

    public:
        ClientHello();
        ~ClientHello();
        ClientHello(const ClientHello& other);

    public:
#ifdef _DEBUG
        void debugOut(std::ostream& out);
#endif
        const coder::ByteArray& encode();
        bool getExtension(uint16_t etype, Extension& ex) const;
        uint8_t getMajorVersion() const;
        uint8_t getMinorVersion() const;
        const coder::ByteArray& getRandom() const;
        void initState();
        CipherSuite getPreferred() const;

    protected:
        void decode();

    private:
        uint32_t gmt;
        coder::ByteArray random;
        coder::ByteArray sessionID;
        uint8_t majorVersion;
        uint8_t minorVersion;
        coder::ByteArray compressionMethods;

        CipherSuiteManager suites;
        ExtensionManager extensions;

};

}

#endif // CLIENTHELLO_H_INCLUDED
