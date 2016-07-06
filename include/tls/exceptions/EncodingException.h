#ifndef CKTLSENCODINGEXCEPTION_H_INCLUDED
#define CKTLSENCODINGEXCEPTION_H_INCLUDED

#include "TLSException.h"
#include <string>

namespace CKTLS {

class EncodingException : public TLSException {

    protected:
        EncodingException() {}

    public:
        EncodingException(const std::string& msg) : TLSException(msg) {}
        EncodingException(const EncodingException& other)
                : TLSException(other) {}

    private:
        EncodingException& operator= (const EncodingException& other);

    public:
        virtual ~EncodingException() {}

};

}

#endif // CKTLSENCODINGEXCEPTION_H_INCLUDED
