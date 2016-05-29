#ifndef CKTLSRECORDEXCEPTION_H_INCLUDED
#define CKTLSRECORDEXCEPTION_H_INCLUDED

#include "exceptions/TLSException.h"
#include <string>

namespace CKTLS {

class RecordException : public TLSException {

    protected:
        RecordException() {}

    public:
        RecordException(const std::string& msg) : TLSException(msg) {}
        RecordException(const RecordException& other)
                : TLSException(other) {}

    private:
        RecordException& operator= (const RecordException& other);

    public:
        virtual ~RecordException() {}

};

}

#endif // CKTLSRECORDEXCEPTION_H_INCLUDED
