#ifndef SERVERHELLODONE_H_INCLUDED
#define SERVERHELLODONE_H_INCLUDED

#include "tls/HandshakeBody.h"

namespace CKTLS {

class ServerHelloDone : public HandshakeBody {

    public:
        ServerHelloDone() {}
        ~ServerHelloDone() {}

    private:
        ServerHelloDone(const ServerHelloDone& other);
        ServerHelloDone& operator= (const ServerHelloDone& other);

    public:
        const coder::ByteArray& encode() { return encoded; }
        void initState() {}

    protected:
        void decode() {}

};

}

#endif  // SERVERHELLODONE_H_INCLUDED
