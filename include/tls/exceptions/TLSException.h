#ifndef CKTLSEXCEPTION_H_INCLUDED
#define CKTLSEXCEPTION_H_INCLUDED

#include <exception>
#include <string>

#ifdef __MACH__
#define EXCEPTION_THROW_SPEC throw()
#else
#define EXCEPTION_THROW_SPEC noexcept
#endif

namespace CKTLS {

class TLSException  : public std::exception {

    protected:
        TLSException() {}
        TLSException(const std::string& msg) : message(msg) {}
        TLSException(const TLSException& other)
                : message(other.message) {}

    private:
        TLSException& operator= (const TLSException& other);

    public:
        ~TLSException() {}

    public:
        const char *what() const EXCEPTION_THROW_SPEC { return message.c_str(); }

    private:
        std::string message;

};

}

#endif // CKTLSEXCEPTION_H_INCLUDED
