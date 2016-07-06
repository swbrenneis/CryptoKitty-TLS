#ifndef STATEEXCEPTION_H_INCLUDED
#define STATEEXCEPTION_H_INCLUDED

#include "TLSException.h"
#include <string>

namespace CKTLS {

class StateException : public TLSException {

    protected:
        StateException() {}

    public:
        StateException(const std::string& msg) : TLSException(msg) {}
        StateException(const StateException& other)
                : TLSException(other) {}

    private:
        StateException& operator= (const StateException& other);

    public:
        virtual ~StateException() {}

};

}

#endif // STATEEXCEPTION_H_INCLUDED
