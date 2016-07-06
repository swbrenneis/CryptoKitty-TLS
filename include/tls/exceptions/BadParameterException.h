#ifndef BADPARAMETEREXCEPTION_H_INCLUDED
#define BADPARAMETEREXCEPTION_H_INCLUDED

#include "TLSException.h"
#include <string>

namespace CKTLS {

class BadParameterException : public TLSException {

    protected:
        BadParameterException() {}

    public:
        BadParameterException(const std::string& msg) : TLSException(msg) {}
        BadParameterException(const BadParameterException& other)
                : TLSException(other) {}

    private:
        BadParameterException& operator= (const BadParameterException& other);

    public:
        virtual ~BadParameterException() {}

};

}

#endif // BADPARAMETEREXCEPTION_H_INCLUDED
