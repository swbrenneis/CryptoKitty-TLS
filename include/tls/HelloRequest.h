#ifndef HELLOREQUEST_H_INCLUDED
#define HELLOREQUEST_H_INCLUDED

#include "HandshakeBody.h"

namespace CKTLS {

class HelloRequest : public HandshakeBody {

    public:
        HelloRequest() {}
        ~HelloRequest() {}

    public:
        const coder::ByteArray& encode() { return encoded; }
        void initState() {}

    protected:
        void decode() {}

};

}

#endif // HELLOREQUEST_H_INCLUDED
