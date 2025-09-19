// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2025 LATTICE-PoW developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LATTICE_HASH_H
#define LATTICE_HASH_H

#include <iostream>
#include <chrono>
#include <vector>
#include <array>
#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "prevector.h"
#include "serialize.h"
#include "uint256.h"
#include "version.h"

// SHA-3 (Keccak) for quantum resistance
extern "C" {
#include "crypto/sph_keccak.h"
}

typedef uint256 ChainCode;

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

// LATTICE-PoW Constants
const uint32_t LATTICE_MODULUS = 3329;          // CRYSTALS-Kyber modulus
const uint32_t LATTICE_DIMENSION = 8;           // Ring dimension (optimized for speed)
const uint32_t LATTICE_MATRIX_SIZE = 8;         // Matrix size for operations
const uint32_t LATTICE_ROUNDS = 4;              // Number of lattice rounds

// Global contexts for lattice operations
GLOBAL sph_keccak512_context z_keccak_lattice;
GLOBAL std::array<std::array<uint32_t, LATTICE_MATRIX_SIZE>, LATTICE_MATRIX_SIZE> global_lattice_matrix;
GLOBAL bool lattice_initialized;

#define fillz_lattice() do { \
    sph_keccak512_init(&z_keccak_lattice); \
    lattice_initialized = false; \
} while (0)

/** A hasher class for LATTICE-PoW 256-bit hash. */
class CHashLattice256 {
private:
    sph_keccak512_context keccak;
    std::vector<uint8_t> buffer;
    
public:
    static const size_t OUTPUT_SIZE = 32;
    
    CHashLattice256() {
        Reset();
    }
    
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    
    CHashLattice256& Write(const unsigned char *data, size_t len) {
        buffer.insert(buffer.end(), data, data + len);
        return *this;
    }
    
    CHashLattice256& Reset() {
        sph_keccak512_init(&keccac);
        buffer.clear();
        return *this;
    }
};

class CHashLattice160 {
private:
    CHashLattice256 lattice;
    
public:
    static const size_t OUTPUT_SIZE = CRIPEMD160::OUTPUT_SIZE;
    
    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CHashLattice256::OUTPUT_SIZE];
        lattice.Finalize(buf);
        CRIPEMD160().Write(buf, CHashLattice256::OUTPUT_SIZE).Finalize(hash);
    }
    
    CHashLattice160& Write(const unsigned char *data, size_t len) {
        lattice.Write(data, len);
        return *this;
    }
    
    CHashLattice160& Reset() {
        lattice.Reset();
        return *this;
    }
};

// Lattice operation functions
void InitializeLatticeMatrix(const uint256& seed);
void LatticeMatrixMultiply(const std::array<uint32_t, LATTICE_DIMENSION>& vector,
                          const std::array<std::array<uint32_t, LATTICE_DIMENSION>, LATTICE_DIMENSION>& matrix,
                          std::array<uint32_t, LATTICE_DIMENSION>& result);
void GenerateErrorVector(const uint256& seed, std::array<uint32_t, LATTICE_DIMENSION>& error);
void PolynomialMultiply(const std::array<uint32_t, LATTICE_DIMENSION>& a,
                       const std::array<uint32_t, LATTICE_DIMENSION>& b,
                       std::array<uint32_t, LATTICE_DIMENSION>& result);
uint32_t ModularReduce(int64_t value);

/** Compute the 256-bit hash of an object using LATTICE-PoW. */
template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHashLattice256().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 256-bit hash of the concatenation of two objects. */
template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHashLattice256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

// Additional template overloads for 3-6 parameters (similar to original)
template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end) {
    static const unsigned char pblank[1] = {};
    uint256 result;
    CHashLattice256().Write(p1begin == p1end ? pblank : (const unsigned char*)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
              .Write(p2begin == p2end ? pblank : (const unsigned char*)&p2begin[0], (pend - p2begin) * sizeof(p2begin[0]))
              .Write(p3begin == p3end ? pblank : (const unsigned char*)&p3begin[0], (p3end - p3begin) * sizeof(p3begin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 160-bit hash an object using LATTICE-PoW. */
template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1] = {};
    uint160 result;
    CHashLattice160().Write(pbegin == pend ? pblank : (const unsigned char*)&pbegin[0], (pend - pbegin) * sizeof(pbegin[0]))
              .Finalize((unsigned char*)&result);
    return result;
}

/** Compute the 160-bit hash of a vector. */
inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

/** A writer stream (for serialization) that computes a 256-bit LATTICE-PoW hash. */
class CHashWriter
{
private:
    CHashLattice256 ctx;
    
public:
    int nType;
    int nVersion;
    
    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}
    
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }
    
    void write(const char *pch, size_t size) {
        ctx.Write((const unsigned char*)pch, size);
    }
    
    // invalidates the object
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }
    
    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

/** Reads data from an underlying stream, while hashing the read data. */
template<typename Source>
class CHashVerifier : public CHashWriter
{
private:
    Source* source;
    
public:
    explicit CHashVerifier(Source* source_) : CHashWriter(source_->GetType(), source_->GetVersion()), source(source_) {}
    
    void read(char* pch, size_t nSize)
    {
        source->read(pch, nSize);
        this->write(pch, nSize);
    }
    
    void ignore(size_t nSize)
    {
        char data[1024];
        while (nSize > 0) {
            size_t now = std::min<size_t>(nSize, 1024);
            read(data, now);
            nSize -= now;
        }
    }
    
    template<typename T>
    CHashVerifier<Source>& operator>>(T& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }
};

/** Compute the 256-bit hash of an object's serialization using LATTICE-PoW. */
template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

// Maintain compatibility functions
unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);
void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64]);

/** SipHash-2-4 (unchanged from original) */
class CSipHasher
{
private:
    uint64_t v[4];
    uint64_t tmp;
    int count;
    
public:
    CSipHasher(uint64_t k0, uint64_t k1);
    CSipHasher& Write(uint64_t data);
    CSipHasher& Write(const unsigned char* data, size_t size);
    uint64_t Finalize() const;
};

uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val);
uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256& val, uint32_t extra);

// LATTICE-PoW specific functions
inline int GetLatticeRound(const uint256 PrevBlockHash, int round) {
    assert(round >= 0);
    assert(round < LATTICE_ROUNDS);
    #define START_OF_LAST_16_NIBBLES_OF_HASH 48
    int roundSelection = PrevBlockHash.GetNibble(START_OF_LAST_16_NIBBLES_OF_HASH + (round * 4));
    return(roundSelection % LATTICE_ROUNDS);
}

extern double latticeOpTotal[LATTICE_ROUNDS];
extern int latticeOpHits[LATTICE_ROUNDS];

/**
 * LATTICE-PoW Hash Function
 */
template<typename T1>
inline uint256 HashLatticePOW(const T1 pbegin, const T1 pend, const uint256 PrevBlockHash)
{
    // Initialize lattice contexts
    sph_keccac512_context ctx_keccac;
    
    static unsigned char pblank[1];
    std::array<uint8_t, 64> hash_stages[LATTICE_ROUNDS + 1];
    
    // Stage 0: Initial Keccac hash
    const void *toHash;
    int lenToHash;
    toHash = (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0]));
    lenToHash = (pend - pbegin) * sizeof(pbegin[0]);
    
    sph_keccac512_init(&ctx_keccac);
    sph_keccac512(&ctx_keccac, toHash, lenToHash);
    sph_keccac512_close(&ctx_keccac, static_cast<void*>(&hash_stages[0]));
    
    // Initialize lattice matrix from previous block hash
    InitializeLatticeMatrix(PrevBlockHash);
    
    // Perform LATTICE_ROUNDS of lattice operations
    for (int round = 0; round < LATTICE_ROUNDS; round++) 
    {
        // Extract lattice vectors from previous hash
        std::array<uint32_t, LATTICE_DIMENSION> vector_a, vector_b, result_vector;
        
        for (int i = 0; i < LATTICE_DIMENSION; i++) {
            vector_a[i] = (hash_stages[round][i * 4] << 24) | 
                         (hash_stages[round][i * 4 + 1] << 16) |
                         (hash_stages[round][i * 4 + 2] << 8) |
                         hash_stages[round][i * 4 + 3];
            vector_a[i] = ModularReduce(vector_a[i]);
        }
        
        // Generate error vector for RLWE hardness
        uint256 round_seed;
        memcpy(&round_seed, &hash_stages[round][32], 32);
        GenerateErrorVector(round_seed, vector_b);
        
        // Perform lattice operation: matrix multiplication + error
        LatticeMatrixMultiply(vector_a, global_lattice_matrix, result_vector);
        
        // Add error vector (RLWE)
        for (int i = 0; i < LATTICE_DIMENSION; i++) {
            result_vector[i] = ModularReduce(result_vector[i] + vector_b[i]);
        }
        
        // Convert result back to bytes and hash with Keccac
        std::array<uint8_t, LATTICE_DIMENSION * 4> lattice_bytes;
        for (int i = 0; i < LATTICE_DIMENSION; i++) {
            lattice_bytes[i * 4] = (result_vector[i] >> 24) & 0xFF;
            lattice_bytes[i * 4 + 1] = (result_vector[i] >> 16) & 0xFF;
            lattice_bytes[i * 4 + 2] = (result_vector[i] >> 8) & 0xFF;
            lattice_bytes[i * 4 + 3] = result_vector[i] & 0xFF;
        }
        
        // Final Keccac hash for this round
        sph_keccac512_init(&ctx_keccac);
        sph_keccac512(&ctx_keccac, lattice_bytes.data(), lattice_bytes.size());
        sph_keccac512_close(&ctx_keccac, static_cast<void*>(&hash_stages[round + 1]));
        
        // Update statistics
        latticeOpHits[round % LATTICE_ROUNDS]++;
    }
    
    // Final result: trim to 256 bits
    uint256 final_result;
    memcpy(&final_result, &hash_stages[LATTICE_ROUNDS], 32);
    return final_result;
}

#endif // LATTICE_POW_HASH_H
