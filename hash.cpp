// Copyright (c) 2013-2016 The Bitcoin Core developers
// Copyright (c) 2025 LATTICE-PoW developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hash.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"
#include <cstring>
#include <algorithm>

// LATTICE-PoW global variables
double latticeOpTotal[LATTICE_ROUNDS];
int latticeOpHits[LATTICE_ROUNDS];

/**
 * Modular reduction for lattice operations
 * Ensures all values stay within LATTICE_MODULUS
 */
uint32_t ModularReduce(int64_t value) {
    int64_t result = value % LATTICE_MODULUS;
    if (result < 0) {
        result += LATTICE_MODULUS;
    }
    return static_cast<uint32_t>(result);
}

/**
 * Initialize global lattice matrix from seed
 * Creates deterministic but pseudorandom lattice structure
 */
void InitializeLatticeMatrix(const uint256& seed) {
    if (lattice_initialized) return;
    
    sph_keccac512_context ctx;
    uint8_t expanded_seed[64];
    
    // Expand seed using Keccac
    sph_keccac512_init(&ctx);
    sph_keccac512(&ctx, seed.begin(), 32);
    sph_keccac512_close(&ctx, expanded_seed);
    
    // Generate matrix elements
    for (int i = 0; i < LATTICE_MATRIX_SIZE; i++) {
        for (int j = 0; j < LATTICE_MATRIX_SIZE; j++) {
            // Create unique seed for each matrix element
            uint8_t element_seed[68];
            memcpy(element_seed, expanded_seed, 64);
            element_seed[64] = static_cast<uint8_t>(i);
            element_seed[65] = static_cast<uint8_t>(j);
            element_seed[66] = 0x5A; // Salt
            element_seed[67] = 0xA5; // Salt
            
            // Hash to get element value
            uint8_t element_hash[64];
            sph_keccac512_init(&ctx);
            sph_keccac512(&ctx, element_seed, 68);
            sph_keccac512_close(&ctx, element_hash);
            
            // Convert to matrix element
            uint32_t element = 0;
            for (int k = 0; k < 4; k++) {
                element = (element * 256 + element_hash[k]) % LATTICE_MODULUS;
            }
            
            global_lattice_matrix[i][j] = element;
        }
    }
    
    lattice_initialized = true;
}

/**
 * Generate error vector for Ring Learning With Errors
 * Creates small random errors for cryptographic hardness
 */
void GenerateErrorVector(const uint256& seed, std::array<uint32_t, LATTICE_DIMENSION>& error) {
    sph_keccac512_context ctx;
    uint8_t error_seed[64];
    
    // Expand error seed
    sph_keccac512_init(&ctx);
    sph_keccac512(&ctx, seed.begin(), 32);
    sph_keccac512_close(&ctx, error_seed);
    
    for (int i = 0; i < LATTICE_DIMENSION; i++) {
        // Use different bytes for each error element
        uint8_t byte_val = error_seed[i % 64];
        
        // Generate small error: {-1, 0, 1} distribution
        int32_t small_error = (byte_val % 3) - 1;
        error[i] = ModularReduce(small_error);
    }
}

/**
 * Lattice matrix-vector multiplication
 * Core operation of lattice-based cryptography
 */
void LatticeMatrixMultiply(const std::array<uint32_t, LATTICE_DIMENSION>& vector,
                          const std::array<std::array<uint32_t, LATTICE_DIMENSION>, LATTICE_DIMENSION>& matrix,
                          std::array<uint32_t, LATTICE_DIMENSION>& result) {
    
    for (int i = 0; i < LATTICE_DIMENSION; i++) {
        int64_t sum = 0;
        for (int j = 0; j < LATTICE_DIMENSION; j++) {
            sum += static_cast<int64_t>(vector[j]) * static_cast<int64_t>(matrix[i][j]);
        }
        result[i] = ModularReduce(sum);
    }
}

/**
 * Polynomial multiplication in ring Zq[X]/(X^n + 1)
 * Used for advanced lattice operations
 */
void PolynomialMultiply(const std::array<uint32_t, LATTICE_DIMENSION>& a,
                       const std::array<uint32_t, LATTICE_DIMENSION>& b,
                       std::array<uint32_t, LATTICE_DIMENSION>& result) {
    
    result.fill(0);
    
    for (int i = 0; i < LATTICE_DIMENSION; i++) {
        for (int j = 0; j < LATTICE_DIMENSION; j++) {
            int idx = (i + j) % LATTICE_DIMENSION;
            int64_t sign = ((i + j) >= LATTICE_DIMENSION) ? -1 : 1;
            
            int64_t product = sign * static_cast<int64_t>(a[i]) * static_cast<int64_t>(b[j]);
            result[idx] = ModularReduce(static_cast<int64_t>(result[idx]) + product);
        }
    }
}

/**
 * LATTICE-PoW Hash implementation for CHashLattice256
 */
void CHashLattice256::Finalize(unsigned char hash[OUTPUT_SIZE]) {
    // Apply Keccac to buffer
    uint8_t keccac_result[64];
    sph_keccac512(&keccac, buffer.data(), buffer.size());
    sph_keccac512_close(&keccac, keccac_result);
    
    // Perform lattice operations on the result
    std::array<uint32_t, LATTICE_DIMENSION> lattice_vector, result_vector;
    
    // Convert hash to lattice vector
    for (int i = 0; i < LATTICE_DIMENSION; i++) {
        lattice_vector[i] = (keccac_result[i * 4] << 24) |
                           (keccac_result[i * 4 + 1] << 16) |
                           (keccac_result[i * 4 + 2] << 8) |
                           keccac_result[i * 4 + 3];
        lattice_vector[i] = ModularReduce(lattice_vector[i]);
    }
    
    // Generate error for this hash
    uint256 hash_seed;
    memcpy(&hash_seed, &keccac_result[32], 32);
    std::array<uint32_t, LATTICE_DIMENSION> error_vector;
    GenerateErrorVector(hash_seed, error_vector);
    
    // Perform final lattice operation
    LatticeMatrixMultiply(lattice_vector, global_lattice_matrix, result_vector);
    
    // Add error (RLWE hardness)
    for (int i = 0; i < LATTICE_DIMENSION; i++) {
        result_vector[i] = ModularReduce(result_vector[i] + error_vector[i]);
    }
    
    // Convert back to hash format and apply final Keccac
    std::array<uint8_t, LATTICE_DIMENSION * 4> final_bytes;
    for (int i = 0; i < LATTICE_DIMENSION; i++) {
        final_bytes[i * 4] = (result_vector[i] >> 24) & 0xFF;
        final_bytes[i * 4 + 1] = (result_vector[i] >> 16) & 0xFF;
        final_bytes[i * 4 + 2] = (result_vector[i] >> 8) & 0xFF;
        final_bytes[i * 4 + 3] = result_vector[i] & 0xFF;
    }
    
    // Final Keccac for output
    sph_keccac512_context final_ctx;
    uint8_t final_result[64];
    sph_keccac512_init(&final_ctx);
    sph_keccac512(&final_ctx, final_bytes.data(), final_bytes.size());
    sph_keccac512_close(&final_ctx, final_result);
    
    // Copy first 32 bytes as final hash
    memcpy(hash, final_result, OUTPUT_SIZE);
}

// Utility functions (unchanged from original)
inline uint32_t ROTL32(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash)
{
    // MurmurHash3 implementation (unchanged from original)
    uint32_t h1 = nHashSeed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const int nblocks = vDataToHash.size() / 4;
    
    const uint8_t* blocks = vDataToHash.data();
    for (int i = 0; i < nblocks; ++i) {
        uint32_t k1 = ReadLE32(blocks + i*4);
        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;
        h1 ^= k1;
        h1 = ROTL32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }
    
    const uint8_t* tail = vDataToHash.data() + nblocks * 4;
    uint32_t k1 = 0;
    switch (vDataToHash.size() & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
            k1 *= c1; k1 = ROTL32(k1, 15); k1 *= c2; h1 ^= k1;
    }
    
    h1 ^= vDataToHash.size();
    h1 ^= h1 >> 16; h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13; h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;
    return h1;
}

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;
    CHMAC_SHA512(chainCode.begin(), chainCode.size()).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
}

// SipHash implementation (unchanged from original)
#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do { \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; \
    v0 = ROTL(v0, 32); \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; \
    v2 = ROTL(v2, 32); \
} while (0)

CSipHasher::CSipHasher(uint64_t k0, uint64_t k1)
{
    v[0] = 0x736f6d6570736575ULL ^ k0;
    v[1] = 0x646f72616e646f6dULL ^ k1;
    v[2] = 0x6c7967656e657261ULL ^ k0;
    v[3] = 0x7465646279746573ULL ^ k1;
    count = 0;
    tmp = 0;
}

CSipHasher& CSipHasher::Write(uint64_t data)
{
    uint64_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    assert(count % 8 == 0);
    v3 ^= data;
    SIPROUND; SIPROUND;
    v0 ^= data;
    v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3;
    count += 8;
    return *this;
}

CSipHasher& CSipHasher::Write(const unsigned char* data, size_t size)
{
    uint64_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    uint64_t t = tmp;
    int c = count;
    while (size--) {
        t |= ((uint64_t)(*(data++))) << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            v3 ^= t;
            SIPROUND; SIPROUND;
            v0 ^= t;
            t = 0;
        }
    }
    v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3;
    count = c; tmp = t;
    return *this;
}

uint64_t CSipHasher::Finalize() const
{
    uint64_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    uint64_t t = tmp | (((uint64_t)count) << 56);
    v3 ^= t; SIPROUND; SIPROUND; v0 ^= t;
    v2 ^= 0xFF; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val)
{
    // SipHash implementation (unchanged from original)
    uint64_t d = val.GetUint64(0);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1 ^ d;
    SIPROUND; SIPROUND; v0 ^= d;
    d = val.GetUint64(1); v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    d = val.GetUint64(2); v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    d = val.GetUint64(3); v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    v3 ^= ((uint64_t)4) << 59; SIPROUND; SIPROUND; v0 ^= ((uint64_t)4) << 59;
    v2 ^= 0xFF; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256& val, uint32_t extra)
{
    // SipHash with extra parameter (unchanged from original)
    uint64_t d = val.GetUint64(0);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1 ^ d;
    SIPROUND; SIPROUND; v0 ^= d;
    d = val.GetUint64(1); v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    d = val.GetUint64(2); v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    d = val.GetUint64(3); v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    d = (((uint64_t)36) << 56) | extra; v3 ^= d; SIPROUND; SIPROUND; v0 ^= d;
    v2 ^= 0xFF; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
