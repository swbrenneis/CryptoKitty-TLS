#include "tls/ExtensionManager.h"
#include "tls/TLSConstants.h"

namespace CKTLS {

// Static initialization;
const uint16_t ExtensionManager::CERT_TYPE = 0x0009;
const uint16_t ExtensionManager::SUPPORTED_CURVES = 0x000a;
const uint16_t ExtensionManager::POINT_FORMATS = 0x000b;
const Extension ExtensionManager::dummy = { coder::Unsigned16(0xffff), coder::ByteArray(0) };

ExtensionManager::ExtensionManager() {
}

ExtensionManager::ExtensionManager(const ExtensionManager& other)
: extensions(other.extensions) {
}

ExtensionManager::~ExtensionManager() {
}

void ExtensionManager::addExtension(const Extension& ext) {

    extensions[ext.type.getValue()] = ext;

}

#ifdef _DEBUG
void ExtensionManager::debugOut(std::ostream& out) const {

    for (ExtConstIter it = extensions.begin(); it != extensions.end(); ++it) {
        out << "Extension.type: " << it->second.type.getValue() << std::endl;
        out << "Extension.data: " << it->second.data.toString() << std::endl;
    }

}
#endif

void ExtensionManager::decode(const coder::ByteArray& encoded) {

    unsigned index = 0;
    while (index < encoded.getLength()) {
        Extension e;
        e.type.decode(encoded.range(index, 2), coder::bigendian);
        index += 2;
        coder::Unsigned16 edl(encoded.range(index, 2), coder::bigendian);
        uint16_t edataLen = edl.getValue();
        index +=2;
        e.data = encoded.range(index, edataLen);
        index += edataLen;
        extensions[e.type.getValue()] = e;
    }

}

coder::ByteArray ExtensionManager::encode() const {

    coder::ByteArray encoded;
    if (extensions.size() > 0) {
        // 2 byte length.
        coder::ByteArray ext;
        for (ExtConstIter it = extensions.begin();
                                    it != extensions.end(); ++it) {
            coder::Unsigned16 u16(it->second.type);
            ext.append(u16.getEncoded(coder::bigendian));
            coder::Unsigned16 edlen(it->second.data.getLength());
            ext.append(edlen.getEncoded(coder::bigendian));
            ext.append(it->second.data);
        }
        coder::Unsigned16 elen(ext.getLength());
        encoded.append(elen.getEncoded(coder::bigendian));
        encoded.append(ext);
    }

    return encoded;

}

const Extension& ExtensionManager::getExtension(uint16_t etype) const {

    ExtConstIter it = extensions.find(etype);
    if (it == extensions.end()) {
        return dummy;
    }

    return it->second;

}

void ExtensionManager::loadDefaults() {

    Extension ext;

    ext.type.setValue(SUPPORTED_CURVES);
    coder::Unsigned16 extCount(4);     // Bytes of extension data
    ext.data.append(extCount.getEncoded(coder::bigendian));
    coder::Unsigned16 curve(secp384r1);
    ext.data.append(curve.getEncoded(coder::bigendian));
    curve.setValue(secp256r1);
    ext.data.append(curve.getEncoded(coder::bigendian));
    extensions[SUPPORTED_CURVES] = ext;
    ext.data.clear();
    ext.type.setValue(CERT_TYPE);
    ext.data.append(0x01);
    ext.data.append(openpgp);
    extensions[CERT_TYPE] = ext;
    ext.data.clear();
    ext.type.setValue(POINT_FORMATS);
    ext.data.append(0x01);
    ext.data.append(0x00); // Uncompressed point format.
    extensions[POINT_FORMATS] = ext;

}

}

