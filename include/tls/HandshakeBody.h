#ifndef HANDSHAKEBODY_H_INCLUDED
#define HANDSHAKEBODY_H_INCLUDED

#include "coder/ByteArray.h"
#include <iostream>

namespace CKTLS {

class HandshakeBody {

    protected:
        HandshakeBody();

    public:
        virtual ~HandshakeBody();

    private:
        HandshakeBody(const HandshakeBody& other);
        HandshakeBody& operator= (const HandshakeBody& other);

    public:
        virtual void debugOut(std::ostream& out) {}
        virtual void decode(const coder::ByteArray& stream);
        virtual const coder::ByteArray& encode()=0;
        virtual void initState()=0;

    protected:
        virtual void decode()=0;

    protected:
        coder::ByteArray encoded;

};

}

#endif // HANDSHAKEBODY_H_INCLUDED
