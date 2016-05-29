#ifndef RECORDPROTOCOL_H_INCLUDED
#define RECORDPROTOCOL_H_INCLUDED

#include "TLSConstants.h"
#include "coder/ByteArray.h"

namespace CKTLS {

class RecordProtocol {

    protected:
        RecordProtocol(ContentType c);
        RecordProtocol(const RecordProtocol& other);

    private:
        RecordProtocol();
        RecordProtocol& operator= (const RecordProtocol& other);

    public:
        virtual ~RecordProtocol();

    public:
        virtual void decodeRecord();
        virtual ContentType decodePreamble(const coder::ByteArray& pre);
        virtual const coder::ByteArray& encodeRecord();
        const coder::ByteArray& getFragment() const;
        uint16_t getFragmentLength() const;
        uint8_t getRecordMajorVersion() const;
        uint8_t getRecordMinorVersion() const;
        ContentType getRecordType() const;
        void setFragment(const coder::ByteArray& frag);

    protected:
        virtual void decode()=0;
        virtual void encode()=0;

    protected:
        ContentType content;
        uint8_t recordMajorVersion;
        uint8_t recordMinorVersion;
        uint16_t fragLength;
        coder::ByteArray fragment;
        coder::ByteArray encodedRec;

        static const uint8_t MAJOR;
        static const uint8_t MINOR;

};

}

#endif  // RECORDPROTOCOL_H_INCLUDED
