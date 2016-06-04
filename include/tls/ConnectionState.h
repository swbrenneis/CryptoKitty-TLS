#ifndef CONNECTIONSTATE_H_INCLUDED
#define CONNECTIONSTATE_H_INCLUDED

#include "tls/TLSConstants.h"
#include "coder/ByteArray.h"

namespace cthread {
    class ThreadLocal;
}

namespace CKTLS {

#ifndef _TLS_THREAD_LOCAL_
class StateContainer;
#endif

class ConnectionState {

    public:
        ConnectionState();
        ConnectionState(const ConnectionState& other);
        ConnectionState& operator= (const ConnectionState& other);
        ~ConnectionState();

    public:
        // Generate the cyptography variables.
        void generateKeys(const coder::ByteArray& premasterSecret);
        // Get the block cipher algorithm.
        BulkCipherAlgorithm getCipherAlgorithm() const;
        // Get the block cipher mode.
        CipherType getCipherType() const;
        // Get the client random bytes for signatures.
        const coder::ByteArray& getClientRandom() const;
        // Get the key for block encryption.
        const coder::ByteArray& getEncryptionKey() const;
        // gets the length of the block encryption key.
        uint32_t getEncryptionKeyLength() const;
        // Get the key for HMAC authentication.
        const coder::ByteArray& getMacKey() const;
        // Get the IV for block encryption.
        const coder::ByteArray& getIV() const;
        // Gets the connection end entity.
        ConnectionEnd getEntity() const;
        // Returns the HMAC algorithm.
        MACAlgorithm getHMAC() const;
        // Return the initialization state.
        bool getInitialized() const;
        // Get the HMAC key length.
        uint32_t getMacKeyLength() const;
        // Get the master secret.
        const coder::ByteArray& getMasterSecret() const;
        // Returns the pseudorandom algorithm.
        PRFAlgorithm getPRF() const;
        // Returns the current sequence number and then increments it.
        int64_t getSequenceNumber() const;
        // Get the server random bytes for signatures.
        const coder::ByteArray& getServerRandom() const;
        // Create the master secret and generate the write keys.
        // Get current and pending state instances.
#ifdef _TLS_THREAD_LOCAL_
        static ConnectionState *getCurrentRead();
        static ConnectionState *getCurrentWrite();
        static ConnectionState *getPendingRead();
        static ConnectionState *getPendingWrite();
#endif
        // Increment the sequence number.
        void incrementSequence();
#ifdef _TLS_THREAD_LOCAL_
        // Promotes the pending read state to current and
        // initializes a new pending state.
        void promoteRead();
        // Promotes the pending write state to current and
        // initializes a new pending state.
        void promoteWrite();
#else
        // Promotes the pending read state to current and
        // initializes a new pending state.
        void promoteRead(StateContainer *container);
        // Promotes the pending write state to current and
        // initializes a new pending state.
        void promoteWrite(StateContainer *container);
#endif
        // Sets the block cipher algorithm.
        void setCipherAlgorithm(BulkCipherAlgorithm alg);
        // Sets the cipher mode.
        void setCipherType(CipherType type);
        // Sets the client random value for signatures.
        void setClientRandom(const coder::ByteArray& rnd);
        // Sets the encryption key length.
        void setEncryptionKeyLength(uint32_t length);
        // Sets the connection end entity.
        void setEntity(ConnectionEnd end);
        // Sets the MAC algorithm.
        void setHMAC(MACAlgorithm m);
        // Indicate the the state is initialized.
        void setInitialized();
        // Sets the server random value for signatures.
        void setServerRandom(const coder::ByteArray& rnd);

    private:
        bool initialized;
        ConnectionEnd entity;
        PRFAlgorithm prf;               // Fixed value. Cannot be set.
        BulkCipherAlgorithm cipher;
        CipherType mode;
        MACAlgorithm mac;
        CompressionMethod compression;  // Fixed value. Cannot be set.
        uint32_t encryptionKeyLength;
        uint32_t blockLength;
        uint32_t fixedIVLength;
        uint32_t recordIVLength;
        uint32_t macLength;
        uint32_t macKeyLength;
        // uint8_t master_secret[48];
        coder::ByteArray masterSecret;
        // uint8_t client_random[32];
        coder::ByteArray clientRandom;
        // uint8_t server_random[32];
        coder::ByteArray serverRandom;
        coder::ByteArray clientWriteMACKey; 
        coder::ByteArray serverWriteMACKey; 
        coder::ByteArray clientWriteKey; 
        coder::ByteArray serverWriteKey; 
        coder::ByteArray clientWriteIV; 
        coder::ByteArray serverWriteIV; 
        int64_t sequenceNumber;


#ifdef _TLS_THREAD_LOCAL_
        /*
         * For no apparent reason, they decided to make the
         * names of thee things really obscure. Client write is used
         * by the server to read incoming client records. Server write
         * is used by the client to read incoming record from the
         * server. Client read is used to send outgoing records to
         * the client. Server read is used to send outgoing records
         * to the server
         */
        static cthread::ThreadLocal *currentRead;
        static cthread::ThreadLocal *currentWrite;
        static cthread::ThreadLocal *pendingRead;
        static cthread::ThreadLocal *pendingWrite;
#endif

};

#ifndef _TLS_THREAD_LOCAL_
class StateContainer {

    public:
        StateContainer() {
            pendingRead = new ConnectionState;
            pendingWrite = new ConnectionState;
            currentRead = 0;
            currentWrite = 0;
        }
        ~StateContainer() {
            delete pendingRead;
            delete pendingWrite;
            delete currentRead;
            delete currentWrite;
        }

    public:
        ConnectionState *getCurrentRead() { return currentRead; }
        ConnectionState *getCurrentWrite() { return currentWrite; }
        ConnectionState *getPendingRead() { return pendingRead; }
        ConnectionState *getPendingWrite() { return pendingWrite; }

   private:
       friend class ConnectionState;
       ConnectionState *currentRead;
       ConnectionState *currentWrite;
       ConnectionState *pendingRead;
       ConnectionState *pendingWrite;

};
#endif

}

#endif  // CONNECTIONSTATE_H_INCLUDED
