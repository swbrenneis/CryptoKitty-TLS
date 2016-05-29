#ifndef CKTLSEXCEPTION_H_INCLUDED
#define CKTLSEXCEPTION_H_INCLUDED

#include <string>

namespace CKTLS {

class TLSException {

    protected:
        TLSException() {}
        TLSException(const std::string& msg) : message(msg) {}
        TLSException(const TLSException& other)
                : message(other.message) {}

    private:
        TLSException& operator= (const TLSException& other);

    public:
        virtual ~TLSException() {}

    public:
        virtual const std::string& what() const { return message; }

    private:
        std::string message;

};

}

#endif // CKTLSBADPARAMETEREXCEPTION_H_INCLUDED
