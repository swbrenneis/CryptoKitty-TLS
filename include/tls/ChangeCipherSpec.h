#ifndef CHANGECIPHERSPEC_H_INCLUDED
#define CHANGECIPHERSPEC_H_INCLUDED

#include "tls/RecordProtocol.h"

namespace CK {
    class Cipher;
}

namespace CKTLS {

class ConnectionState;

class ChangeCipherSpec : public RecordProtocol {

    public:
        ChangeCipherSpec();
        ~ChangeCipherSpec();

    private:
        ChangeCipherSpec(const ChangeCipherSpec& other);
        ChangeCipherSpec& operator= (const ChangeCipherSpec& other);

    protected:
        void decode();
        void encode();

    private:
        CK::Cipher *getCipher(ConnectionState *state) const;

        static const uint8_t MAJORVERSION;
        static const uint8_t MINORVERSION;

};

}

#endif  // CHANGECIPHERSPEC_H_INCLUDED
