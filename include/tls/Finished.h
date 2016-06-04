#ifndef FINISHED_H_INCLUDED
#define FINISHED_H_INCLUDED

#include "tls/HandshakeBody.h"

namespace CKTLS {

#ifndef _TLS_THREAD_LOCAL_
class StateContainer;
#endif

class Finished : public HandshakeBody {

    public:
#ifdef _TLS_THREAD_LOCAL_
        Finished();
#else
        Finished(StateContainer *holder);
#endif
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
#ifndef _TLS_THREAD_LOCAL_
        StateContainer *holder;
#endif

};

}

#endif // FINISHED_H_INCLUDED
