#include "tls/ConnectionState.h"
#include "digest/SHA256.h"
#include "mac/HMAC.h"
#include "tls/exceptions/StateException.h"
#include "tls/exceptions/BadParameterException.h"
#include <iostream>

#ifdef _TLS_THREAD_LOCAL_
#include "cthread/ThreadLocal.h"
#endif

namespace CKTLS {

#ifdef _TLS_THREAD_LOCAL_
// Static initialization.
cthread::ThreadLocal *ConnectionState::currentRead = 0;
cthread::ThreadLocal *ConnectionState::currentWrite = 0;
cthread::ThreadLocal *ConnectionState::pendingRead = 0;
cthread::ThreadLocal *ConnectionState::pendingWrite = 0;

typedef cthread::TypedThreadLocal<ConnectionState> LocalConnectionState;
#endif

ConnectionState::ConnectionState()
: initialized(false),
  prf(tls_prf_sha256),
  compression(cm_null),
  sequenceNumber(0) {
}

ConnectionState::~ConnectionState() {
}

ConnectionState::ConnectionState(const ConnectionState& other)
: initialized(false),
  entity(other.entity),
  prf(other.prf),
  cipher(other.cipher),
  mode(other.mode),
  mac(other.mac),
  compression(other.compression),
  encryptionKeyLength(other.encryptionKeyLength),
  blockLength(other.blockLength),
  fixedIVLength(other.fixedIVLength),
  recordIVLength(other.recordIVLength),
  macLength(other.macLength),
  macKeyLength(other.macKeyLength),
  masterSecret(other.masterSecret),
  clientRandom(other.clientRandom),
  serverRandom(other.serverRandom),
  clientWriteMACKey(other.clientWriteMACKey),
  serverWriteMACKey(other.serverWriteMACKey),
  clientWriteKey(other.clientWriteKey),
  serverWriteKey(other.serverWriteKey),
  clientWriteIV(other.clientWriteIV),
  serverWriteIV(other.serverWriteIV),
  sequenceNumber(0) {
  }

/*
 * Generate the master secret and the client and server write keys.
 */
void ConnectionState::generateKeys(const coder::ByteArray& premasterSecret) {

    masterSecret.clear();
    CK::HMAC prf(new CK::SHA256);
    prf.setKey(premasterSecret);
    coder::ByteArray seed("master secret");
    seed.append(clientRandom);
    seed.append(serverRandom);
    prf.setMessage(seed);
    coder::ByteArray phash(prf.getHMAC());
    masterSecret.append(phash);
    while (masterSecret.getLength() < 48) {
        prf.setMessage(phash);
        phash = prf.getHMAC();
        masterSecret.append(phash);
    }
    masterSecret = masterSecret.range(0, 48);
    //std::cout << "Master Secret = " << masterSecret << std::endl;

    prf.setKey(masterSecret);
    unsigned keyLength = (encryptionKeyLength + fixedIVLength
                                                + macKeyLength) * 2;
    seed = "key expansion";
    seed.append(serverRandom);
    seed.append(clientRandom);
    prf.setMessage(seed);
    phash = prf.getHMAC();
    coder::ByteArray keyBytes(phash);
    while (keyBytes.getLength() < keyLength) {
        prf.setMessage(phash);
        phash = prf.getHMAC();
        keyBytes.append(phash);
    }
    clientWriteMACKey = keyBytes.range(0, macKeyLength);
    serverWriteMACKey = keyBytes.range(macKeyLength, macKeyLength);
    clientWriteKey = keyBytes.range(macKeyLength*2, encryptionKeyLength);
    serverWriteKey = keyBytes.range((macKeyLength*2)+encryptionKeyLength,
                                                encryptionKeyLength);
    serverWriteIV = keyBytes.range((macKeyLength*2)+(encryptionKeyLength*2),
                                                fixedIVLength);
    clientWriteIV = keyBytes.range((macKeyLength*2)+(encryptionKeyLength*2)
                                                +fixedIVLength,fixedIVLength);

}

BulkCipherAlgorithm ConnectionState::getCipherAlgorithm() const {

    return cipher;

}

CipherType ConnectionState::getCipherType() const {

    return mode;

}

const coder::ByteArray& ConnectionState::getClientRandom() const {

    return clientRandom;

}

#ifdef _TLS_THREAD_LOCAL_
ConnectionState *ConnectionState::getCurrentRead() {

    if (currentRead == 0) {
        throw StateException("Current read state not valid");
    }

    return dynamic_cast<LocalConnectionState*>(currentRead)->getLocal();

}

ConnectionState *ConnectionState::getCurrentWrite() {

    if (currentWrite == 0) {
        throw StateException("Current write state not valid");
    }

    return dynamic_cast<LocalConnectionState*>(currentWrite)->getLocal();

}
#endif

const coder::ByteArray& ConnectionState::getEncryptionKey() const {

    return entity == server ? clientWriteKey : serverWriteKey;

}

uint32_t ConnectionState::getEncryptionKeyLength() const {

    return encryptionKeyLength * 8;

}

const coder::ByteArray& ConnectionState::getIV() const {

    return entity == server ? clientWriteIV : serverWriteIV;

}

const coder::ByteArray& ConnectionState::getMacKey() const {

    return entity == server ? clientWriteMACKey : serverWriteMACKey;

}

/*
 * Return the connection entity.
 */
ConnectionEnd ConnectionState::getEntity() const {

    return entity;

}

MACAlgorithm ConnectionState::getHMAC() const {

    return mac;

}

uint32_t ConnectionState::getMacKeyLength() const {

    return macKeyLength;

}

const coder::ByteArray& ConnectionState::getMasterSecret() const {

    return masterSecret;

}

#ifdef _TLS_THREAD_LOCAL_
ConnectionState *ConnectionState::getPendingRead() {

    if (pendingRead == 0) {
        pendingRead = new LocalConnectionState;
    }

    LocalConnectionState *lcs = dynamic_cast<LocalConnectionState*>(pendingRead);
    ConnectionState *pr = lcs->getLocal();
    if (pr == 0) {
        pr = new ConnectionState;
        lcs->setLocal(pr);
    }

    return pr;

}

ConnectionState *ConnectionState::getPendingWrite() {

    if (pendingWrite == 0) {
        pendingWrite = new LocalConnectionState;
    }

    LocalConnectionState *lcs = dynamic_cast<LocalConnectionState*>(pendingWrite);
    ConnectionState *pw = lcs->getLocal();
    if (pw == 0) {
        pw = new ConnectionState;
        lcs->setLocal(pw);
    }

    return pw;

}
#endif

/*
 * Returns the current sequence number.
 */
int64_t ConnectionState::getSequenceNumber() const {

    return sequenceNumber;

}

const coder::ByteArray& ConnectionState::getServerRandom() const {

    return serverRandom;

}

/*
 * Increments the current sequence number.
 */
void ConnectionState::incrementSequence() {

    sequenceNumber++;

}

#ifdef _TLS_THREAD_LOCAL_
/*
 * promote the pending read state. Throws StateException if
 * the pending read state is uninitialized.
 */
void ConnectionState::promoteRead() {

    if (pendingRead == 0 || !getPendingRead()->initialized) {
        throw StateException("Pending read state not initialized.");
    }

    if (currentRead == 0) {
        currentRead = new LocalConnectionState;
    }

    LocalConnectionState *lcs = dynamic_cast<LocalConnectionState*>(currentRead);
    delete lcs->getLocal();
    lcs->setLocal(new ConnectionState(*getPendingRead()));
    getPendingRead()->initialized = false;

}

/*
 * promote the pending write state. Throws StateException if
 * the pending write state is uninitialized.
 */
void ConnectionState::promoteWrite() {

    if (pendingWrite == 0 || !getPendingWrite()->initialized) {
        throw StateException("Pending write state not initialized.");
    }

    if (currentWrite == 0) {
        currentWrite = new LocalConnectionState;
    }

    LocalConnectionState *lcs = dynamic_cast<LocalConnectionState*>(currentWrite);
    delete lcs->getLocal();
    lcs->setLocal(new ConnectionState(*getPendingWrite()));
    getPendingWrite()->initialized = false;

}
#else
/*
 * promote the pending read state. Throws StateException if
 * the pending read state is uninitialized.
 */
void ConnectionState::promoteRead(StateContainer *holder) {

    if (holder->pendingRead == 0 || !holder->pendingRead->initialized) {
        throw StateException("Pending read state not initialized.");
    }

    delete holder->currentRead;
    holder->currentRead = holder->pendingRead;
    holder->pendingRead = new ConnectionState(*holder->currentRead);
    holder->pendingRead->initialized = false;

}

/*
 * promote the pending write state. Throws StateException if
 * the pending write state is uninitialized.
 */
void ConnectionState::promoteWrite(StateContainer *holder) {

    if (holder->pendingWrite == 0 || !holder->pendingWrite->initialized) {
        throw StateException("Pending write state not initialized.");
    }

    delete holder->currentWrite;
    holder->currentWrite = holder->pendingWrite;
    holder->pendingWrite = new ConnectionState(*holder->currentWrite);
    holder->pendingWrite->initialized = false;

}
#endif

void ConnectionState::setCipherAlgorithm(BulkCipherAlgorithm alg) {

    cipher = alg;

    switch (cipher) {
        case rc4:
            // TODO
            break;
        case tdes:
            // TODO
            break;
        case aes:
            blockLength = 16;
            if (mode == block) {
                fixedIVLength = 16;
            }
            break;
        default:
            throw StateException("Invalid block cipher algorithm");
    }

}

void ConnectionState::setCipherType(CipherType type) {

    mode = type;

    switch (mode) {
        case stream:
            // Needs RC4 cipher.
            break;
        case block:
            // CBC mode. IV length = cipher block lenght
            break;
        case aead:
            // GCM mode. IV length = 12 for performance reasons.
            fixedIVLength = 12;
            break;
        default:
            throw StateException("Invalid HMAC algorithm");
    }

}

void ConnectionState::setClientRandom(const coder::ByteArray& rnd) {

    clientRandom = rnd;

}

void ConnectionState::setEncryptionKeyLength(uint32_t keyLength) {

    if (keyLength % 8 != 0) {
        throw BadParameterException("Invalid key size");
    }

    encryptionKeyLength = keyLength / 8;

}

void ConnectionState::setEntity(ConnectionEnd end) {

    entity = end;

}

void ConnectionState::setHMAC(MACAlgorithm m) {

    mac = m;

    switch (mac) {
        case mac_null:
            macLength = 0;
            break;
        case hmac_md5:
            macLength = macKeyLength = 16;
            break;
        case hmac_sha1:
            macLength = macKeyLength = 20;
            break;
        case hmac_sha256:
            macLength = macKeyLength = 32;
            break;
        case hmac_sha384:
            macLength = macKeyLength = 48;
            break;
        case hmac_sha512:
            macLength = macKeyLength = 64;
            break;
        default:
            throw StateException("Invalid HMAC algorithm");
    }

}

void ConnectionState::setInitialized() {

    initialized = true;

}

void ConnectionState::setServerRandom(const coder::ByteArray& rnd) {

    serverRandom = rnd;

}

}

