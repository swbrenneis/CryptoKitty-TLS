#ifndef PLAINTEXT_H_INCLUDED
#define PLAINTEXT_H_INCLUDED

#include "tls/RecordProtocol.h"

namespace CKTLS {

class Plaintext : public RecordProtocol {

    protected:
        Plaintext();

    private:
        Plaintext(const Plaintext& other);
        Plaintext& operator= (const Plaintext& other);

    public:
        virtual ~Plaintext();

};

}

#endif  // PLAINTEXT_H_INCLUDED
