#ifndef STATEEXCEPTION_H_INCLUDED
#define STATEEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CKTLS {

class StateException : public CK::Exception {

    protected:
        StateException() {}

    public:
        StateException(const std::string& msg) : CK::Exception(msg) {}
        StateException(const CK::Exception& other)
                : CK::Exception(other) {}

    private:
        StateException& operator= (const StateException& other);

    public:
        virtual ~StateException() {}

};

}

#endif // STATEEXCEPTION_H_INCLUDED
