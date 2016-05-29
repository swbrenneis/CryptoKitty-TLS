#ifndef EXTENSIONMANAGER_H_INCLUDED
#define EXTENSIONMANAGER_H_INCLUDED

#include "coder/ByteArray.h"
#include "coder/Unsigned16.h"
#include <deque>
#include <map>
#include <iostream>

namespace CKTLS {

struct Extension {
    coder::Unsigned16 type;
    coder::ByteArray data;
};

typedef std::deque<Extension> ExtensionList;
typedef ExtensionList::const_iterator ExtConstIter;

class ExtensionManager {

    public:
        ExtensionManager();
        ExtensionManager(const ExtensionManager& other);
        ~ExtensionManager();

    private:
        ExtensionManager& operator= (const ExtensionManager& other);

    public:
        void addExtension(const Extension& ext);
#ifdef _DEBUG
        void debugOut(std::ostream& out) const;
#endif
        void decode(const coder::ByteArray& encoded);
        coder::ByteArray encode() const;
        const Extension& getExtension(uint16_t etype) const;
        void loadDefaults();

    public:
        static const uint16_t CERT_TYPE;
        static const uint16_t SUPPORTED_CURVES;
        static const uint16_t POINT_FORMATS;

    private:
        typedef std::map<uint32_t, Extension> ExtensionMap;
        typedef ExtensionMap::const_iterator ExtConstIter;
        ExtensionMap extensions;
        static const Extension dummy;

};

}

#endif  // EXTENSIONMANAGER_H_INCLUDED
