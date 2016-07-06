#ifndef CHANGECIPHERSPEC_H_INCLUDED
#define CHANGECIPHERSPEC_H_INCLUDED

#include "RecordProtocol.h"

namespace CK {
    class Cipher;
}

namespace CKTLS {

class ConnectionState;
#ifndef _TLS_THREAD_LOCAL_
class StateContainer;
#endif

class ChangeCipherSpec : public RecordProtocol {

    public:
#ifdef _TLS_THREAD_LOCAL_
        ChangeCipherSpec();
#else
        ChangeCipherSpec(StateContainer *holder);
#endif
        ~ChangeCipherSpec();

    private:
        ChangeCipherSpec(const ChangeCipherSpec& other);
        ChangeCipherSpec& operator= (const ChangeCipherSpec& other);

    protected:
        void decode();
        void encode();

    private:
        CK::Cipher *getCipher(ConnectionState *state) const;

    private:
#ifndef _TLS_THREAD_LOCAL_
        StateContainer *holder;
#endif

        static const uint8_t MAJORVERSION;
        static const uint8_t MINORVERSION;

};

}

#endif  // CHANGECIPHERSPEC_H_INCLUDED
