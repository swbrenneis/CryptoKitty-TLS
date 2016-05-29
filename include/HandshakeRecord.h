#ifndef HANDSHAKERECORD_H_INCLUDED
#define HANDSHAKERECORD_H_INCLUDED

#include "RecordProtocol.h"

namespace CKTLS {

class HandshakeBody;
class ConnectionState;

class HandshakeRecord : public RecordProtocol {

    public:
        HandshakeRecord();
        HandshakeRecord(HandshakeType h);
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

};

}
#endif  // HANDSHAKERECORD_H_INCLUDED
