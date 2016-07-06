#ifndef HANDSHAKERECORD_H_INCLUDED
#define HANDSHAKERECORD_H_INCLUDED

#include "RecordProtocol.h"

namespace CKTLS {

class HandshakeBody;
class ConnectionState;

#ifndef _TLS_THREAD_LOCAL_
class StateContainer;
#endif

class HandshakeRecord : public RecordProtocol {

    public:
#ifdef _TLS_THREAD_LOCAL_
        HandshakeRecord();
        HandshakeRecord(HandshakeType h);
#else
        HandshakeRecord(StateContainer* holder);
        HandshakeRecord(HandshakeType h, StateContainer *holder);
#endif
        HandshakeRecord(const HandshakeRecord& other);
        HandshakeRecord& operator= (const HandshakeRecord& other);
        ~HandshakeRecord();

    public:
        HandshakeBody *getBody();
        HandshakeType getHandshakeType() const;

    protected:
        void decode();
        void encode();

    private:
        HandshakeBody *body;
        HandshakeType type;
#ifndef _TLS_THREAD_LOCAL_
        StateContainer *holder;
#endif

};

}
#endif  // HANDSHAKERECORD_H_INCLUDED
