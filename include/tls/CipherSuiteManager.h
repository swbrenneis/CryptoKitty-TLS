#ifndef CIPHERSUITEMANAGER_H_INCLUDED
#define CIPHERSUITEMANAGER_H_INCLUDED

#include "tls/TLSConstants.h"
#include "coder/ByteArray.h"
#include <deque>
#include <iostream>

namespace CKTLS {

typedef std::deque<CipherSuite> CipherSuiteList;
typedef CipherSuiteList::const_iterator CipherConstIter;
typedef CipherSuiteList::iterator CipherIter;

/*
 * Singleton.
 */
class CipherSuiteManager {

    public:
        CipherSuiteManager();
        CipherSuiteManager(const CipherSuiteManager& other);
        ~CipherSuiteManager();

    private:
        CipherSuiteManager& operator= (const CipherSuiteManager& other);

    public:
#ifdef _DEBUG
        void debugOut(std::ostream& out) const;
#endif
        void decode(const coder::ByteArray& encoded);
        coder::ByteArray encode() const;
        CipherSuite getServerSuite() const;
        bool isCurve(CipherSuite c) const;
        void loadPreferred();
        CipherSuite matchCipherSuite() const;
        void setPreferred(CipherSuite c);

    private:
        void initialize();

    private:
        CipherSuiteList suites;
        static CipherSuiteList preferred;

};

}

#endif  // CIPHERSUITEMANAGER_H_INCLUDED
