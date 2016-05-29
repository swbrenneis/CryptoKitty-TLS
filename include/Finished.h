#ifndef FINISHED_H_INCLUDED
#define FINISHED_H_INCLUDED

#include "HandshakeBody.h"

namespace CKTLS {

class Finished : public HandshakeBody {

    public:
        Finished();
        ~Finished();

    public:
        bool authenticate(const coder::ByteArray& fin) const;
        const coder::ByteArray& encode();
        void initState() {}
        void initState(const coder::ByteArray& finished);

    protected:
        void decode();

    private:
        coder::ByteArray finished;

};

}

#endif // FINISHED_H_INCLUDED
