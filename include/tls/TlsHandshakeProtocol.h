#ifndef TLSHANDSHAKEPROTOCOL_H_INCLUDED
#define TLSHANDSHAKEPROTOCOL_H_INCLUDED

#include "data/ByteArray.h"
#include "data/Scalar32.h"
#include <cstdint>

namespace TLS {

typedef uint8_t *opaque;
typedef CK::Scalar32 uint32;

struct uint16 {
    uint8_t bytes[2];
    unsigned unsignedValue() {
        unsigned result = bytes[0];
        result = result << 8;
        result |= bytes[1];
        return result;
    }
};

struct uint24 {
    uint8_t bytes[3];
    unsigned unsignedValue() {
        unsigned result = 0;
        for (int n = 0; n < 3; ++n) {
            result = result << 8;
            result |= bytes[n];
        }
        return result;
    }
};

// uint8_t
enum ContentType { change_cipher_spec=20, alert=21, handshake=22,
        application_data=23 };

struct ProtocolVersion {
    uint8_t major;
    uint8_t minor;
};

struct TLSPlaintext{
    ContentType type;
    ProtocolVersion version;
    uint16 length;
    opaque fragment;
};

// uint8_t
enum HandshakeType { hello_request=0, client_hello=1, server_hello=2,
                    certificate=11, server_key_exchange=12,
                    certificate_request=13, server_hello_done=14,
                    certificate_verify=15, client_key_exchange=16,
                    finished=20 };

template <typename R>
struct Handshake {
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* bytes in message */
    /* select (HandshakeType) {
        case hello_request:       HelloRequest;
        case client_hello:        ClientHello;
        case server_hello:        ServerHello;
        case certificate:         Certificate;
        case server_key_exchange: ServerKeyExchange;
        case certificate_request: CertificateRequest;
        case server_hello_done:   ServerHelloDone;
        case certificate_verify:  CertificateVerify;
        case client_key_exchange: ClientKeyExchange;
        case finished:            Finished;
    } body; */
    R body;
};

struct Random {
    uint32 gmt_unix_time;
    opaque random_bytes[28];
};

typedef CK::ByteArray SessionID;
struct CipherSelector {
    uint8_t select[2];
};
typedef std::deque<CipherSelector> CipherSuite;

// uint8_t
enum CompressionMethodEnum { null=0 };
typedef CK::ByteArray CompressionMethod;
struct ExtensionSpec {
    uint16 extension_type;
    CK::ByteArray extension_data;
};
typedef std::deque<ExtensionSpec> Extension;

struct ClientHello {
    ProtocolVersion client_version;
    Random random;
    SessionID session_id;
    CipherSuite cipher_suites;
    CompressionMethod compression_methods;
    Extension extensions;
};

}
#endif  // TLSHANDSHAKEPROTOCOL_H_INCLUDED
