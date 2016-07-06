#include "tls/PGPCertificate.h"
#include "tls/exceptions/RecordException.h"
#include "tls/exceptions/EncodingException.h"
#include "openpgp/packet/Encrypted.h"
#include "openpgp/mode/PGPCFM.h"
#include "openpgp/key/String2Key.h"
#include "openpgp/encode/ArmoredData.h"
#include <CryptoKitty-C/cipher/AES.h>
#include <coder/Unsigned16.h>
#include <coder/Unsigned32.h>

namespace CKTLS {

// TODO: Maybe copy on write semantics?
PGPCertificate::PGPCertificate()
: publicKey(0) {
}

PGPCertificate::PGPCertificate(const coder::ByteArray& encoded) {

    decode(encoded);

}

PGPCertificate::PGPCertificate(std::istream& in) {

    decode(in);

}

PGPCertificate::PGPCertificate(const PGPCertificate& other)
: publicKey(new CKPGP::PublicKey(*other.publicKey)),
  userIds(other.userIds),
  userAttributes(other.userAttributes),
  subKeys(other.subKeys),
  revocation(other.revocation) {
}

PGPCertificate::~PGPCertificate() {

    delete publicKey;

}

PGPCertificate& PGPCertificate::operator= (const PGPCertificate& other) {

    publicKey = new CKPGP::PublicKey(*other.publicKey);
    userIds = other.userIds;
    userAttributes = other.userAttributes;
    subKeys = other.subKeys;
    revocation = other.revocation;
    return *this;

}

void PGPCertificate::addUserID(const CKPGP::UserID& uid, const CKPGP::Signature& sig) {

    bool found = false;
    for (IdIter it = userIds.begin(); it != userIds.end() && !found; ++it) {
        if (it->id == uid) {
            it->sigs.push_back(sig);
            found = true;
        }
    }
    if (!found) {
        SignedID sid;
        sid.id = uid;
        sid.sigs.push_back(sig);
        userIds.push_back(sid);
    }

}

void PGPCertificate::decode(const coder::ByteArray& encoded) {

    CKPGP::Packet *packet = CKPGP::Packet::decodePacket(encoded);
    if (packet->getTag() != CKPGP::Packet::PUBLICKEY) {
        throw RecordException("Invalid certificate");
    }
    publicKey = dynamic_cast<CKPGP::PublicKey*>(packet);
    unsigned index = publicKey->getPacketLength() + packet->getHeaderLength();

    bool userSection = true;
    // Yuck.
    while (index < encoded.getLength()) {
        packet = CKPGP::Packet::decodePacket(encoded.range(index,
                                                        encoded.getLength() - index));
        index += packet->getPacketLength() + packet->getHeaderLength();
        if (packet->getTag() == CKPGP::Packet::USERID) {
            if (!userSection) {
                throw RecordException("Invalid certificate");
            }
            SignedID id;
            id.id = dynamic_cast<CKPGP::UserID*>(packet);
            bool signatures = true;
            while (index < encoded.getLength() && signatures) {
                //Peek at the packet before updating the index
                packet = CKPGP::Packet::decodePacket(encoded.range(index,
                                                            encoded.getLength() - index));
                if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
                    index += packet->getPacketLength() + packet->getHeaderLength();
                    id.sigs.push_back(dynamic_cast<CKPGP::Signature*>(packet));
                }
                else {
                    signatures = false;
                }
            }
            userIds.push_back(id);
        }
        else if (packet->getTag() == CKPGP::Packet::USERATTRIBUTE) {
            if (!userSection) {
                throw RecordException("Invalid certificate");
            }
            SignedAttr attr;
            attr.attr = dynamic_cast<CKPGP::UserAttribute*>(packet);
            bool signatures = true;
            while (index < encoded.getLength() && signatures) {
                //Peek at the packet before updating the index
                packet = CKPGP::Packet::decodePacket(encoded.range(index,
                                                        encoded.getLength() - index));
                if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
                    index += packet->getPacketLength() + packet->getHeaderLength();
                    attr.sigs.push_back(dynamic_cast<CKPGP::Signature*>(packet));
                }
                else {
                    signatures = false;
                }
            }
            userAttributes.push_back(attr);
        }
        else if (packet->getTag() == CKPGP::Packet::PUBLICSUBKEY) {
            userSection = false;
            SignedSubkey sub;
            sub.sub = dynamic_cast<CKPGP::PublicSubkey*>(packet);
            packet = CKPGP::Packet::decodePacket(encoded.range(index, encoded.getLength() - index));
            index += packet->getPacketLength() + packet->getHeaderLength();
            sub.sig = dynamic_cast<CKPGP::Signature*>(packet);
            subKeys.push_back(sub);
        }
        else if (packet->getTag() == CKPGP::Packet::SIGNATURE) {
            userSection = false;
            revocation.push_back(dynamic_cast<CKPGP::Signature*>(packet));
        }
        else {
            throw RecordException("Invalid certificate");
        }
    }

}

void PGPCertificate::decode(std::istream& in) {

    CKPGP::ArmoredData armored;
    armored.decode(in);
    CKPGP::Packet *packet = CKPGP::Packet::decodePacket(armored.getData());

    if (packet->getTag() != CKPGP::Packet::ENCRYPTED) {
        throw EncodingException("Invalid PGP packet");
    }

    CKPGP::Encrypted *enc = dynamic_cast<CKPGP::Encrypted*>(packet);
    CKPGP::PGPCFM cfm(new CK::AES(CK::AES::AES128));

    coder::ByteArray salt("dopoodoo");
    CKPGP::String2Key s2k(CKPGP::String2Key::SHA256, salt);
    coder::ByteArray key(s2k.generateKey("carve up my pot roast", 128));

    decode(cfm.decrypt(enc->getCiphertext(), key));

}

uint32_t PGPCertificate::decodePGPLength(std::istream& in, coder::ByteArray& lBytes) const {

    char octets[5];
    uint8_t *ubuf = reinterpret_cast<uint8_t*>(octets);
    in.get(octets[0]);
    lBytes.append(ubuf[0]);
    if (ubuf[0] < 192) {
        return ubuf[0];
    }
    else if (ubuf[0] == 0xff) {
        in.get(octets, 4);
        lBytes.append(ubuf, 4);
        coder::Unsigned32 len(lBytes.range(1, 4), coder::bigendian);
        return len.getValue();
    }
    else {
        in.get(octets[0]);
        lBytes.append(ubuf[0]);
        coder::Unsigned16 len(lBytes, coder::bigendian);
        return len.getValue();
    }

}

coder::ByteArray PGPCertificate::encode() {

    // PGP structures are a series of self-contained packets.
    coder::ByteArray encoded;
    encoded.append(publicKey->getEncoded());
    if (encoded.getLength() == 0) {
        throw RecordException("Invalid public key");
    }

    // User IDs. May be unsigned.
    if (userIds.size() == 0) {
        throw RecordException("No associated user ids");
    }
    for (IdIter it = userIds.begin(); it != userIds.end(); ++it) {
        encoded.append(it->id.getEncoded());
        for (SigIter sit = it->sigs.begin(); sit != it->sigs.end(); ++sit) {
            encoded.append(sit->getEncoded());
        }
    }

    // User attributes. May be unsigned.
    for (AttrIter it = userAttributes.begin(); it != userAttributes.end(); ++it) {
        encoded.append(it->attr.getEncoded());
        for (SigIter sit = it->sigs.begin(); sit != it->sigs.end(); ++sit) {
            encoded.append(sit->getEncoded());
        }
    }

    // Subkeys. Must be signed.
    for (SubIter it = subKeys.begin(); it != subKeys.end(); ++it) {
        encoded.append(it->sub.getEncoded());
        encoded.append(it->sig.getEncoded());
    }

    // Revocation signatures.
    for (SigIter it = revocation.begin(); it != revocation.end(); ++it) {
        encoded.append(it->getEncoded());
    }

    return encoded;

}

CKPGP::PublicKey *PGPCertificate::getPublicKey() {

    return publicKey;

}

void PGPCertificate::setPublicKey(CKPGP::PublicKey *pk) {

    delete publicKey;
    publicKey = pk;

}

}
