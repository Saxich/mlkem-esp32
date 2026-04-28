/*
 * FIPS 202 (SHA-3 / SHAKE) — Keccak-p[1600] permutation
 *
 * Based on the eXtended Keccak Code Package (XKCP)
 *   https://github.com/XKCP/XKCP
 *   Designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.
 *   License: CC0-1.0 (public domain dedication)
 *
 * This file is part of a bachelor thesis implementation of ML-KEM (FIPS 203)
 * targeting the ESP32 microcontroller (Xtensa LX6, 32-bit, in-order pipeline).
 * See CREDITS.md for full attribution and README for implementation overview.
 *
 * Optimizations applied over the base XKCP implementation:
 *
 *   1. Structured XOR5 — balanced binary tree reduction of the theta step:
 *        XOR5(a,b,c,d,e) = ((a^b) ^ (c^d)) ^ e
 *      Reduces the dependency chain depth from 4 to 3, avoiding pipeline stalls.
 *
 *   2. Chi step arithmetic from wolfSSL (GPL-3.0-or-later)
 *      The standard NOT-AND form is replaced with equivalent NOT-free expressions:
 *        a ^ (~b & c)  ==  a ^ (c & (b ^ c))        [applied at positions 0, 2, 4]
 *        a ^ (~b & c)  ==  (a ^ b) ^ (b | c)        [applied at positions 1, 3]
 *      Temporaries t12 = b^c and t34 = d^e are each reused across two outputs,
 *      reducing the chi step from 15 operations (5× NOT, AND, XOR) to 12.
 *
 *   3. Bufferless SHAKE absorption — shake128_absorb and shake256_prf write
 *      directly into the sponge state, eliminating intermediate copy buffers.
 *
 * Licensing:
 *   Base XKCP code — CC0-1.0 (public domain dedication)
 *     http://creativecommons.org/publicdomain/zero/1.0/
 *   Chi step arithmetic derived from wolfSSL — GPL-3.0-or-later
 *     https://www.gnu.org/licenses/gpl-3.0.html
 *   This file as a whole is therefore subject to GPL-3.0-or-later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stddef.h>
#include <stdint.h>
#include "fips202.h"

#define NROUNDS 24

/* ---------------------------------------------------------------- */
/* Low-level Keccak-p[1600] permutation - XKCP 32-bit optimized    */
/* ---------------------------------------------------------------- */

#include <stdint.h>
#include <string.h>
#include "SnP-Relaned.h"

#define ROL32(a, offset) ((((uint32_t)a) << (offset)) ^ (((uint32_t)a) >> (32-(offset))))

// shortening the dependency chain: depth 3 instead of 4
#define XOR5(a,b,c,d,e) (((a) ^ (b)) ^ ((c) ^ (d)) ^ (e))

/* Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
#define prepareToBitInterleaving(low, high, temp, temp0, temp1) \
        temp0 = (low); \
        temp = (temp0 ^ (temp0 >>  1)) & 0x22222222UL;  temp0 = temp0 ^ temp ^ (temp <<  1); \
        temp = (temp0 ^ (temp0 >>  2)) & 0x0C0C0C0CUL;  temp0 = temp0 ^ temp ^ (temp <<  2); \
        temp = (temp0 ^ (temp0 >>  4)) & 0x00F000F0UL;  temp0 = temp0 ^ temp ^ (temp <<  4); \
        temp = (temp0 ^ (temp0 >>  8)) & 0x0000FF00UL;  temp0 = temp0 ^ temp ^ (temp <<  8); \
        temp1 = (high); \
        temp = (temp1 ^ (temp1 >>  1)) & 0x22222222UL;  temp1 = temp1 ^ temp ^ (temp <<  1); \
        temp = (temp1 ^ (temp1 >>  2)) & 0x0C0C0C0CUL;  temp1 = temp1 ^ temp ^ (temp <<  2); \
        temp = (temp1 ^ (temp1 >>  4)) & 0x00F000F0UL;  temp1 = temp1 ^ temp ^ (temp <<  4); \
        temp = (temp1 ^ (temp1 >>  8)) & 0x0000FF00UL;  temp1 = temp1 ^ temp ^ (temp <<  8);

#define toBitInterleavingAndXOR(low, high, even, odd, temp, temp0, temp1) \
        prepareToBitInterleaving(low, high, temp, temp0, temp1) \
        even ^= (temp0 & 0x0000FFFF) | (temp1 << 16); \
        odd ^= (temp0 >> 16) | (temp1 & 0xFFFF0000);

#define toBitInterleavingAndAND(low, high, even, odd, temp, temp0, temp1) \
        prepareToBitInterleaving(low, high, temp, temp0, temp1) \
        even &= (temp0 & 0x0000FFFF) | (temp1 << 16); \
        odd &= (temp0 >> 16) | (temp1 & 0xFFFF0000);

#define toBitInterleavingAndSet(low, high, even, odd, temp, temp0, temp1) \
        prepareToBitInterleaving(low, high, temp, temp0, temp1) \
        even = (temp0 & 0x0000FFFF) | (temp1 << 16); \
        odd = (temp0 >> 16) | (temp1 & 0xFFFF0000);

/* Credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
#define prepareFromBitInterleaving(even, odd, temp, temp0, temp1) \
        temp0 = (even); \
        temp1 = (odd); \
        temp = (temp0 & 0x0000FFFF) | (temp1 << 16); \
        temp1 = (temp0 >> 16) | (temp1 & 0xFFFF0000); \
        temp0 = temp; \
        temp = (temp0 ^ (temp0 >>  8)) & 0x0000FF00UL;  temp0 = temp0 ^ temp ^ (temp <<  8); \
        temp = (temp0 ^ (temp0 >>  4)) & 0x00F000F0UL;  temp0 = temp0 ^ temp ^ (temp <<  4); \
        temp = (temp0 ^ (temp0 >>  2)) & 0x0C0C0C0CUL;  temp0 = temp0 ^ temp ^ (temp <<  2); \
        temp = (temp0 ^ (temp0 >>  1)) & 0x22222222UL;  temp0 = temp0 ^ temp ^ (temp <<  1); \
        temp = (temp1 ^ (temp1 >>  8)) & 0x0000FF00UL;  temp1 = temp1 ^ temp ^ (temp <<  8); \
        temp = (temp1 ^ (temp1 >>  4)) & 0x00F000F0UL;  temp1 = temp1 ^ temp ^ (temp <<  4); \
        temp = (temp1 ^ (temp1 >>  2)) & 0x0C0C0C0CUL;  temp1 = temp1 ^ temp ^ (temp <<  2); \
        temp = (temp1 ^ (temp1 >>  1)) & 0x22222222UL;  temp1 = temp1 ^ temp ^ (temp <<  1);

#define fromBitInterleaving(even, odd, low, high, temp, temp0, temp1) \
        prepareFromBitInterleaving(even, odd, temp, temp0, temp1) \
        low = temp0; \
        high = temp1;

#define fromBitInterleavingAndXOR(even, odd, lowIn, highIn, lowOut, highOut, temp, temp0, temp1) \
        prepareFromBitInterleaving(even, odd, temp, temp0, temp1) \
        lowOut = lowIn ^ temp0; \
        highOut = highIn ^ temp1;

void KeccakP1600_SetBytesInLaneToZero(KeccakP1600_plain32_state *state, unsigned int lanePosition, unsigned int offset, unsigned int length)
{
    uint8_t laneAsBytes[8];
    uint32_t low, high;
    uint32_t temp, temp0, temp1;
    uint32_t *stateAsHalfLanes = state->A;

    memset(laneAsBytes, 0xFF, offset);
    memset(laneAsBytes+offset, 0x00, length);
    memset(laneAsBytes+offset+length, 0xFF, 8-offset-length);
    low = *((uint32_t*)(laneAsBytes+0));
    high = *((uint32_t*)(laneAsBytes+4));


    toBitInterleavingAndAND(low, high, stateAsHalfLanes[lanePosition*2+0], stateAsHalfLanes[lanePosition*2+1], temp, temp0, temp1);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_Initialize(KeccakP1600_plain32_state *state)
{
    memset(state, 0, 200);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddByte(KeccakP1600_plain32_state *state, unsigned char byte, unsigned int offset)
{
    unsigned int lanePosition = offset/8;
    unsigned int offsetInLane = offset%8;
    uint32_t low, high;
    uint32_t temp, temp0, temp1;
    uint32_t *stateAsHalfLanes = state->A;

    if (offsetInLane < 4) {
        low = (uint32_t)byte << (offsetInLane*8);
        high = 0;
    }
    else {
        low = 0;
        high = (uint32_t)byte << ((offsetInLane-4)*8);
    }
    toBitInterleavingAndXOR(low, high, stateAsHalfLanes[lanePosition*2+0], stateAsHalfLanes[lanePosition*2+1], temp, temp0, temp1);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytesInLane(KeccakP1600_plain32_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    uint8_t laneAsBytes[8];
    uint32_t low, high;
    uint32_t temp, temp0, temp1;
    uint32_t *stateAsHalfLanes = state->A;

    memset(laneAsBytes, 0, 8);
    memcpy(laneAsBytes+offset, data, length);
    low = *((uint32_t*)(laneAsBytes+0));
    high = *((uint32_t*)(laneAsBytes+4));

    toBitInterleavingAndXOR(low, high, stateAsHalfLanes[lanePosition*2+0], stateAsHalfLanes[lanePosition*2+1], temp, temp0, temp1);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddLanes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int laneCount)
{
    const uint32_t * pI = (const uint32_t *)data;
    uint32_t * pS = state->A;
    uint32_t t, x0, x1;
    int i;
    for (i = laneCount-1; i >= 0; --i) {
        toBitInterleavingAndXOR(*(pI++), *(pI++), *(pS++), *(pS++), t, x0, x1)
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_AddBytes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_AddBytes(state, data, offset, length, KeccakP1600_AddLanes, KeccakP1600_AddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteBytesInLane(KeccakP1600_plain32_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
    // Optimized: combine SetBytesInLaneToZero and AddBytesInLane into single operation
    // to avoid double bit-interleaving conversion
    uint8_t laneAsBytes[8];
    uint32_t low, high;
    uint32_t temp, temp0, temp1;
    uint32_t *stateAsHalfLanes = state->A;

    // Build the lane with zeros before offset, data, and zeros after
    memset(laneAsBytes, 0, offset);
    memcpy(laneAsBytes+offset, data, length);
    memset(laneAsBytes+offset+length, 0, 8-offset-length);

    low = *((uint32_t*)(laneAsBytes+0));
    high = *((uint32_t*)(laneAsBytes+4));

    // Directly set (overwrite) the interleaved state - single conversion
    toBitInterleavingAndSet(low, high, stateAsHalfLanes[lanePosition*2+0], stateAsHalfLanes[lanePosition*2+1], temp, temp0, temp1);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteLanes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int laneCount)
{
    const uint32_t * pI = (const uint32_t *)data;
    uint32_t * pS = (uint32_t *)state;
    uint32_t t, x0, x1;
    int i;
    for (i = laneCount-1; i >= 0; --i) {
        toBitInterleavingAndSet(*(pI++), *(pI++), *(pS++), *(pS++), t, x0, x1)
    }

}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteBytes(KeccakP1600_plain32_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_OverwriteBytes(state, data, offset, length, KeccakP1600_OverwriteLanes, KeccakP1600_OverwriteBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_OverwriteWithZeroes(KeccakP1600_plain32_state *state, unsigned int byteCount)
{
    uint32_t *stateAsHalfLanes = state->A;
    unsigned int i;

    for(i=0; i<byteCount/8; i++) {
        stateAsHalfLanes[i*2+0] = 0;
        stateAsHalfLanes[i*2+1] = 0;
    }
    if (byteCount%8 != 0)
        KeccakP1600_SetBytesInLaneToZero(state, byteCount/8, 0, byteCount%8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytesInLane(const KeccakP1600_plain32_state *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
    const uint32_t *stateAsHalfLanes = state->A;
    uint32_t low, high, temp, temp0, temp1;
    uint8_t laneAsBytes[8];

    fromBitInterleaving(stateAsHalfLanes[lanePosition*2], stateAsHalfLanes[lanePosition*2+1], low, high, temp, temp0, temp1);
    *((uint32_t*)(laneAsBytes+0)) = low;
    *((uint32_t*)(laneAsBytes+4)) = high;

    memcpy(data, laneAsBytes+offset, length);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractLanes(const KeccakP1600_plain32_state *state, unsigned char *data, unsigned int laneCount)
{
    uint32_t * pI = (uint32_t *)data;
    const uint32_t * pS = ( const uint32_t *)state;
    uint32_t t, x0, x1;
    int i;
    for (i = laneCount-1; i >= 0; --i) {
        fromBitInterleaving(*(pS++), *(pS++), *(pI++), *(pI++), t, x0, x1)
    }

}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractBytes(const KeccakP1600_plain32_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_ExtractBytes(state, data, offset, length, KeccakP1600_ExtractLanes, KeccakP1600_ExtractBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytesInLane(const KeccakP1600_plain32_state *state, unsigned int lanePosition, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    const uint32_t *stateAsHalfLanes = state->A;
    uint32_t low, high, temp, temp0, temp1;
    uint8_t laneAsBytes[8];
    unsigned int i;

    fromBitInterleaving(stateAsHalfLanes[lanePosition*2], stateAsHalfLanes[lanePosition*2+1], low, high, temp, temp0, temp1);
    *((uint32_t*)(laneAsBytes+0)) = low;
    *((uint32_t*)(laneAsBytes+4)) = high;


    // Optimized: use word-sized XOR operations instead of byte-by-byte
    const uint8_t *src = laneAsBytes + offset;
    i = 0;

    // Process 4 bytes at a time if aligned and length permits
    if (length >= 4 && ((uintptr_t)(input) & 3) == 0 && ((uintptr_t)(output) & 3) == 0) {
        while (i + 4 <= length) {
            *((uint32_t*)(output + i)) = *((const uint32_t*)(input + i)) ^ *((const uint32_t*)(src + i));
            i += 4;
        }
    }

    // Process remaining bytes
    while (i < length) {
        output[i] = input[i] ^ src[i];
        i++;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddLanes(const KeccakP1600_plain32_state *state, const unsigned char *input, unsigned char *output, unsigned int laneCount)
{
    const uint32_t * pI = (const uint32_t *)input;
    uint32_t * pO = (uint32_t *)output;
    const uint32_t * pS = (const uint32_t *)state;
    uint32_t t, x0, x1;
    int i;
    for (i = laneCount-1; i >= 0; --i) {
        fromBitInterleavingAndXOR(*(pS++), *(pS++), *(pI++), *(pI++), *(pO++), *(pO++), t, x0, x1)
    }
}
/* ---------------------------------------------------------------- */

void KeccakP1600_ExtractAndAddBytes(const KeccakP1600_plain32_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    SnP_ExtractAndAddBytes(state, input, output, offset, length, KeccakP1600_ExtractAndAddLanes, KeccakP1600_ExtractAndAddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

static const uint32_t KeccakF1600RoundConstants_int2[2*24+1] =
{
    0x00000001UL,    0x00000000UL,
    0x00000000UL,    0x00000089UL,
    0x00000000UL,    0x8000008bUL,
    0x00000000UL,    0x80008080UL,
    0x00000001UL,    0x0000008bUL,
    0x00000001UL,    0x00008000UL,
    0x00000001UL,    0x80008088UL,
    0x00000001UL,    0x80000082UL,
    0x00000000UL,    0x0000000bUL,
    0x00000000UL,    0x0000000aUL,
    0x00000001UL,    0x00008082UL,
    0x00000000UL,    0x00008003UL,
    0x00000001UL,    0x0000808bUL,
    0x00000001UL,    0x8000000bUL,
    0x00000001UL,    0x8000008aUL,
    0x00000001UL,    0x80000081UL,
    0x00000000UL,    0x80000081UL,
    0x00000000UL,    0x80000008UL,
    0x00000000UL,    0x00000083UL,
    0x00000000UL,    0x80008003UL,
    0x00000001UL,    0x80008088UL,
    0x00000000UL,    0x80000088UL,
    0x00000001UL,    0x00008000UL,
    0x00000000UL,    0x80008082UL,
    0x000000FFUL
};

#define KeccakRound0() \
        Cx  = XOR5(Abu0, Agu0, Aku0, Amu0, Asu0); \
        Du1 = XOR5(Abe1, Age1, Ake1, Ame1, Ase1); \
        Da0 = Cx ^ ROL32(Du1, 1); \
        Cz  = XOR5(Abu1, Agu1, Aku1, Amu1, Asu1); \
        Du0 = XOR5(Abe0, Age0, Ake0, Ame0, Ase0); \
        Da1 = Cz ^ Du0; \
        Cw  = XOR5(Abi0, Agi0, Aki0, Ami0, Asi0); \
        Do0 = Cw ^ ROL32(Cz, 1); \
        Cy  = XOR5(Abi1, Agi1, Aki1, Ami1, Asi1); \
        Do1 = Cy ^ Cx; \
        Cx  = XOR5(Aba0, Aga0, Aka0, Ama0, Asa0); \
        De0 = Cx ^ ROL32(Cy, 1); \
        Cz  = XOR5(Aba1, Aga1, Aka1, Ama1, Asa1); \
        De1 = Cz ^ Cw; \
        Cy  = XOR5(Abo1, Ago1, Ako1, Amo1, Aso1); \
        Di0 = Du0 ^ ROL32(Cy, 1); \
        Cw  = XOR5(Abo0, Ago0, Ako0, Amo0, Aso0); \
        Di1 = Du1^Cw; \
        Du0 = Cw^ROL32(Cz, 1); \
        Du1 = Cy^Cx; \
\
        Ba = (Aba0^Da0); \
        Be = ROL32((Age0^De0), 22); \
        Bi = ROL32((Aki1^Di1), 22); \
        Bo = ROL32((Amo1^Do1), 11); \
        Bu = ROL32((Asu0^Du0),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba0 = Ba ^ ( Bi & t12); \
        Aba0 ^= *(pRoundConstants++); \
        Age0 = t12 ^ ( Bi | Bo); \
        Aki1 = Bi  ^ ( Bu & t34); \
        Amo1 = t34 ^ ( Bu | Ba); \
        Asu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Ba = (Aba1^Da1); \
        Be = ROL32((Age1^De1), 22); \
        Bi = ROL32((Aki0^Di0), 21); \
        Bo = ROL32((Amo0^Do0), 10); \
        Bu = ROL32((Asu1^Du1),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba1 = Ba ^ ( Bi & t12); \
        Aba1 ^= *(pRoundConstants++); \
        Age1 = t12 ^ ( Bi | Bo); \
        Aki0 = Bi  ^ ( Bu & t34); \
        Amo0 = t34 ^ ( Bu | Ba); \
        Asu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Aka1^Da1),  2); \
        Bo = ROL32((Ame1^De1), 23); \
        Bu = ROL32((Asi1^Di1), 31); \
        Ba = ROL32((Abo0^Do0), 14); \
        Be = ROL32((Agu0^Du0), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka1 = Ba ^ ( Bi & t12); \
        Ame1 = t12 ^ ( Bi | Bo); \
        Asi1 = Bi  ^ ( Bu & t34); \
        Abo0 = t34 ^ ( Bu | Ba); \
        Agu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Aka0^Da0),  1); \
        Bo = ROL32((Ame0^De0), 22); \
        Bu = ROL32((Asi0^Di0), 30); \
        Ba = ROL32((Abo1^Do1), 14); \
        Be = ROL32((Agu1^Du1), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka0 = Ba ^ ( Bi & t12); \
        Ame0 = t12 ^ ( Bi | Bo); \
        Asi0 = Bi  ^ ( Bu & t34); \
        Abo1 = t34 ^ ( Bu | Ba); \
        Agu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Asa0^Da0),  9); \
        Ba = ROL32((Abe1^De1),  1); \
        Be = ROL32((Agi0^Di0),  3); \
        Bi = ROL32((Ako1^Do1), 13); \
        Bo = ROL32((Amu0^Du0),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa0 = Ba ^ ( Bi & t12); \
        Abe1 = t12 ^ ( Bi | Bo); \
        Agi0 = Bi  ^ ( Bu & t34); \
        Ako1 = t34 ^ ( Bu | Ba); \
        Amu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Asa1^Da1),  9); \
        Ba = (Abe0^De0); \
        Be = ROL32((Agi1^Di1),  3); \
        Bi = ROL32((Ako0^Do0), 12); \
        Bo = ROL32((Amu1^Du1),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa1 = Ba ^ ( Bi & t12); \
        Abe0 = t12 ^ ( Bi | Bo); \
        Agi1 = Bi  ^ ( Bu & t34); \
        Ako0 = t34 ^ ( Bu | Ba); \
        Amu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Aga0^Da0), 18); \
        Bi = ROL32((Ake0^De0),  5); \
        Bo = ROL32((Ami1^Di1),  8); \
        Bu = ROL32((Aso0^Do0), 28); \
        Ba = ROL32((Abu1^Du1), 14); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga0 = Ba ^ ( Bi & t12); \
        Ake0 = t12 ^ ( Bi | Bo); \
        Ami1 = Bi  ^ ( Bu & t34); \
        Aso0 = t34 ^ ( Bu | Ba); \
        Abu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Aga1^Da1), 18); \
        Bi = ROL32((Ake1^De1),  5); \
        Bo = ROL32((Ami0^Di0),  7); \
        Bu = ROL32((Aso1^Do1), 28); \
        Ba = ROL32((Abu0^Du0), 13); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga1 = Ba ^ ( Bi & t12); \
        Ake1 = t12 ^ ( Bi | Bo); \
        Ami0 = Bi  ^ ( Bu & t34); \
        Aso1 = t34 ^ ( Bu | Ba); \
        Abu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Ama1^Da1), 21); \
        Bu = ROL32((Ase0^De0),  1); \
        Ba = ROL32((Abi0^Di0), 31); \
        Be = ROL32((Ago1^Do1), 28); \
        Bi = ROL32((Aku1^Du1), 20); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama1 = Ba ^ ( Bi & t12); \
        Ase0 = t12 ^ ( Bi | Bo); \
        Abi0 = Bi  ^ ( Bu & t34); \
        Ago1 = t34 ^ ( Bu | Ba); \
        Aku1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Ama0^Da0), 20); \
        Bu = ROL32((Ase1^De1),  1); \
        Ba = ROL32((Abi1^Di1), 31); \
        Be = ROL32((Ago0^Do0), 27); \
        Bi = ROL32((Aku0^Du0), 19); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama0 = Ba ^ ( Bi & t12); \
        Ase1 = t12 ^ ( Bi | Bo); \
        Abi1 = Bi  ^ ( Bu & t34); \
        Ago0 = t34 ^ ( Bu | Ba); \
        Aku0 = Bu  ^ ( Be & (Ba ^ Be))

#define KeccakRound1() \
        Cx  = XOR5(Asu0, Agu0, Amu0, Abu1, Aku1); \
        Du1 = XOR5(Age1, Ame0, Abe0, Ake1, Ase1); \
        Da0 = Cx ^ ROL32(Du1, 1); \
        Cz  = XOR5(Asu1, Agu1, Amu1, Abu0, Aku0); \
        Du0 = XOR5(Age0, Ame1, Abe1, Ake0, Ase0); \
        Da1 = Cz ^ Du0; \
        Cw  = XOR5(Aki1, Asi1, Agi0, Ami1, Abi0); \
        Do0 = Cw ^ ROL32(Cz, 1); \
        Cy  = XOR5(Aki0, Asi0, Agi1, Ami0, Abi1); \
        Do1 = Cy ^ Cx; \
        Cx  = XOR5(Aba0, Aka1, Asa0, Aga0, Ama1); \
        De0 = Cx ^ ROL32(Cy, 1); \
        Cz  = XOR5(Aba1, Aka0, Asa1, Aga1, Ama0); \
        De1 = Cz ^ Cw; \
        Cy  = XOR5(Amo0, Abo1, Ako0, Aso1, Ago0); \
        Di0 = Du0 ^ ROL32(Cy, 1); \
        Cw  = XOR5(Amo1, Abo0, Ako1, Aso0, Ago1); \
        Di1 = Du1^Cw; \
        Du0 = Cw^ROL32(Cz, 1); \
        Du1 = Cy^Cx; \
\
        Ba = (Aba0^Da0); \
        Be = ROL32((Ame1^De0), 22); \
        Bi = ROL32((Agi1^Di1), 22); \
        Bo = ROL32((Aso1^Do1), 11); \
        Bu = ROL32((Aku1^Du0),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba0 = Ba ^ ( Bi & t12); \
        Aba0 ^= *(pRoundConstants++); \
        Ame1 = t12 ^ ( Bi | Bo); \
        Agi1 = Bi  ^ ( Bu & t34); \
        Aso1 = t34 ^ ( Bu | Ba); \
        Aku1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Ba = (Aba1^Da1); \
        Be = ROL32((Ame0^De1), 22); \
        Bi = ROL32((Agi0^Di0), 21); \
        Bo = ROL32((Aso0^Do0), 10); \
        Bu = ROL32((Aku0^Du1),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba1 = Ba ^ ( Bi & t12); \
        Aba1 ^= *(pRoundConstants++); \
        Ame0 = t12 ^ ( Bi | Bo); \
        Agi0 = Bi  ^ ( Bu & t34); \
        Aso0 = t34 ^ ( Bu | Ba); \
        Aku0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Asa1^Da1),  2); \
        Bo = ROL32((Ake1^De1), 23); \
        Bu = ROL32((Abi1^Di1), 31); \
        Ba = ROL32((Amo1^Do0), 14); \
        Be = ROL32((Agu0^Du0), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa1 = Ba ^ ( Bi & t12); \
        Ake1 = t12 ^ ( Bi | Bo); \
        Abi1 = Bi  ^ ( Bu & t34); \
        Amo1 = t34 ^ ( Bu | Ba); \
        Agu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Asa0^Da0),  1); \
        Bo = ROL32((Ake0^De0), 22); \
        Bu = ROL32((Abi0^Di0), 30); \
        Ba = ROL32((Amo0^Do1), 14); \
        Be = ROL32((Agu1^Du1), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa0 = Ba ^ ( Bi & t12); \
        Ake0 = t12 ^ ( Bi | Bo); \
        Abi0 = Bi  ^ ( Bu & t34); \
        Amo0 = t34 ^ ( Bu | Ba); \
        Agu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Ama1^Da0),  9); \
        Ba = ROL32((Age1^De1),  1); \
        Be = ROL32((Asi1^Di0),  3); \
        Bi = ROL32((Ako0^Do1), 13); \
        Bo = ROL32((Abu1^Du0),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama1 = Ba ^ ( Bi & t12); \
        Age1 = t12 ^ ( Bi | Bo); \
        Asi1 = Bi  ^ ( Bu & t34); \
        Ako0 = t34 ^ ( Bu | Ba); \
        Abu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Ama0^Da1),  9); \
        Ba = (Age0^De0); \
        Be = ROL32((Asi0^Di1),  3); \
        Bi = ROL32((Ako1^Do0), 12); \
        Bo = ROL32((Abu0^Du1),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama0 = Ba ^ ( Bi & t12); \
        Age0 = t12 ^ ( Bi | Bo); \
        Asi0 = Bi  ^ ( Bu & t34); \
        Ako1 = t34 ^ ( Bu | Ba); \
        Abu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Aka1^Da0), 18); \
        Bi = ROL32((Abe1^De0),  5); \
        Bo = ROL32((Ami0^Di1),  8); \
        Bu = ROL32((Ago1^Do0), 28); \
        Ba = ROL32((Asu1^Du1), 14); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka1 = Ba ^ ( Bi & t12); \
        Abe1 = t12 ^ ( Bi | Bo); \
        Ami0 = Bi  ^ ( Bu & t34); \
        Ago1 = t34 ^ ( Bu | Ba); \
        Asu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Aka0^Da1), 18); \
        Bi = ROL32((Abe0^De1),  5); \
        Bo = ROL32((Ami1^Di0),  7); \
        Bu = ROL32((Ago0^Do1), 28); \
        Ba = ROL32((Asu0^Du0), 13); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka0 = Ba ^ ( Bi & t12); \
        Abe0 = t12 ^ ( Bi | Bo); \
        Ami1 = Bi  ^ ( Bu & t34); \
        Ago0 = t34 ^ ( Bu | Ba); \
        Asu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Aga1^Da1), 21); \
        Bu = ROL32((Ase0^De0),  1); \
        Ba = ROL32((Aki1^Di0), 31); \
        Be = ROL32((Abo1^Do1), 28); \
        Bi = ROL32((Amu1^Du1), 20); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga1 = Ba ^ ( Bi & t12); \
        Ase0 = t12 ^ ( Bi | Bo); \
        Aki1 = Bi  ^ ( Bu & t34); \
        Abo1 = t34 ^ ( Bu | Ba); \
        Amu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Aga0^Da0), 20); \
        Bu = ROL32((Ase1^De1),  1); \
        Ba = ROL32((Aki0^Di1), 31); \
        Be = ROL32((Abo0^Do0), 27); \
        Bi = ROL32((Amu0^Du0), 19); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga0 = Ba ^ ( Bi & t12); \
        Ase1 = t12 ^ ( Bi | Bo); \
        Aki0 = Bi  ^ ( Bu & t34); \
        Abo0 = t34 ^ ( Bu | Ba); \
        Amu0 = Bu  ^ ( Be & (Ba ^ Be))

#define KeccakRound2() \
        Cx  = XOR5(Aku1, Agu0, Abu1, Asu1, Amu1); \
        Du1 = XOR5(Ame0, Ake0, Age0, Abe0, Ase1); \
        Da0 = Cx ^ ROL32(Du1, 1); \
        Cz  = XOR5(Aku0, Agu1, Abu0, Asu0, Amu0); \
        Du0 = XOR5(Ame1, Ake1, Age1, Abe1, Ase0); \
        Da1 = Cz ^ Du0; \
        Cw  = XOR5(Agi1, Abi1, Asi1, Ami0, Aki1); \
        Do0 = Cw ^ ROL32(Cz, 1); \
        Cy  = XOR5(Agi0, Abi0, Asi0, Ami1, Aki0); \
        Do1 = Cy ^ Cx; \
        Cx  = XOR5(Aba0, Asa1, Ama1, Aka1, Aga1); \
        De0 = Cx ^ ROL32(Cy, 1); \
        Cz  = XOR5(Aba1, Asa0, Ama0, Aka0, Aga0); \
        De1 = Cz ^ Cw; \
        Cy  = XOR5(Aso0, Amo0, Ako1, Ago0, Abo0); \
        Di0 = Du0 ^ ROL32(Cy, 1); \
        Cw  = XOR5(Aso1, Amo1, Ako0, Ago1, Abo1); \
        Di1 = Du1^Cw; \
        Du0 = Cw^ROL32(Cz, 1); \
        Du1 = Cy^Cx; \
\
        Ba = (Aba0^Da0); \
        Be = ROL32((Ake1^De0), 22); \
        Bi = ROL32((Asi0^Di1), 22); \
        Bo = ROL32((Ago0^Do1), 11); \
        Bu = ROL32((Amu1^Du0),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba0 = Ba ^ ( Bi & t12); \
        Aba0 ^= *(pRoundConstants++); \
        Ake1 = t12 ^ ( Bi | Bo); \
        Asi0 = Bi  ^ ( Bu & t34); \
        Ago0 = t34 ^ ( Bu | Ba); \
        Amu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Ba = (Aba1^Da1); \
        Be = ROL32((Ake0^De1), 22); \
        Bi = ROL32((Asi1^Di0), 21); \
        Bo = ROL32((Ago1^Do0), 10); \
        Bu = ROL32((Amu0^Du1),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba1 = Ba ^ ( Bi & t12); \
        Aba1 ^= *(pRoundConstants++); \
        Ake0 = t12 ^ ( Bi | Bo); \
        Asi1 = Bi  ^ ( Bu & t34); \
        Ago1 = t34 ^ ( Bu | Ba); \
        Amu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Ama0^Da1),  2); \
        Bo = ROL32((Abe0^De1), 23); \
        Bu = ROL32((Aki0^Di1), 31); \
        Ba = ROL32((Aso1^Do0), 14); \
        Be = ROL32((Agu0^Du0), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama0 = Ba ^ ( Bi & t12); \
        Abe0 = t12 ^ ( Bi | Bo); \
        Aki0 = Bi  ^ ( Bu & t34); \
        Aso1 = t34 ^ ( Bu | Ba); \
        Agu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Ama1^Da0),  1); \
        Bo = ROL32((Abe1^De0), 22); \
        Bu = ROL32((Aki1^Di0), 30); \
        Ba = ROL32((Aso0^Do1), 14); \
        Be = ROL32((Agu1^Du1), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama1 = Ba ^ ( Bi & t12); \
        Abe1 = t12 ^ ( Bi | Bo); \
        Aki1 = Bi  ^ ( Bu & t34); \
        Aso0 = t34 ^ ( Bu | Ba); \
        Agu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Aga1^Da0),  9); \
        Ba = ROL32((Ame0^De1),  1); \
        Be = ROL32((Abi1^Di0),  3); \
        Bi = ROL32((Ako1^Do1), 13); \
        Bo = ROL32((Asu1^Du0),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga1 = Ba ^ ( Bi & t12); \
        Ame0 = t12 ^ ( Bi | Bo); \
        Abi1 = Bi  ^ ( Bu & t34); \
        Ako1 = t34 ^ ( Bu | Ba); \
        Asu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Aga0^Da1),  9); \
        Ba = (Ame1^De0); \
        Be = ROL32((Abi0^Di1),  3); \
        Bi = ROL32((Ako0^Do0), 12); \
        Bo = ROL32((Asu0^Du1),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga0 = Ba ^ ( Bi & t12); \
        Ame1 = t12 ^ ( Bi | Bo); \
        Abi0 = Bi  ^ ( Bu & t34); \
        Ako0 = t34 ^ ( Bu | Ba); \
        Asu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Asa1^Da0), 18); \
        Bi = ROL32((Age1^De0),  5); \
        Bo = ROL32((Ami1^Di1),  8); \
        Bu = ROL32((Abo1^Do0), 28); \
        Ba = ROL32((Aku0^Du1), 14); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa1 = Ba ^ ( Bi & t12); \
        Age1 = t12 ^ ( Bi | Bo); \
        Ami1 = Bi  ^ ( Bu & t34); \
        Abo1 = t34 ^ ( Bu | Ba); \
        Aku0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Asa0^Da1), 18); \
        Bi = ROL32((Age0^De1),  5); \
        Bo = ROL32((Ami0^Di0),  7); \
        Bu = ROL32((Abo0^Do1), 28); \
        Ba = ROL32((Aku1^Du0), 13); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa0 = Ba ^ ( Bi & t12); \
        Age0 = t12 ^ ( Bi | Bo); \
        Ami0 = Bi  ^ ( Bu & t34); \
        Abo0 = t34 ^ ( Bu | Ba); \
        Aku1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Aka0^Da1), 21); \
        Bu = ROL32((Ase0^De0),  1); \
        Ba = ROL32((Agi1^Di0), 31); \
        Be = ROL32((Amo0^Do1), 28); \
        Bi = ROL32((Abu0^Du1), 20); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka0 = Ba ^ ( Bi & t12); \
        Ase0 = t12 ^ ( Bi | Bo); \
        Agi1 = Bi  ^ ( Bu & t34); \
        Amo0 = t34 ^ ( Bu | Ba); \
        Abu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Aka1^Da0), 20); \
        Bu = ROL32((Ase1^De1),  1); \
        Ba = ROL32((Agi0^Di1), 31); \
        Be = ROL32((Amo1^Do0), 27); \
        Bi = ROL32((Abu1^Du0), 19); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka1 = Ba ^ ( Bi & t12); \
        Ase1 = t12 ^ ( Bi | Bo); \
        Agi0 = Bi  ^ ( Bu & t34); \
        Amo1 = t34 ^ ( Bu | Ba); \
        Abu1 = Bu  ^ ( Be & (Ba ^ Be))

#define KeccakRound3() \
        Cx  = XOR5(Amu1, Agu0, Asu1, Aku0, Abu0); \
        Du1 = XOR5(Ake0, Abe1, Ame1, Age0, Ase1); \
        Da0 = Cx ^ ROL32(Du1, 1); \
        Cz  = XOR5(Amu0, Agu1, Asu0, Aku1, Abu1); \
        Du0 = XOR5(Ake1, Abe0, Ame0, Age1, Ase0); \
        Da1 = Cz ^ Du0; \
        Cw  = XOR5(Asi0, Aki0, Abi1, Ami1, Agi1); \
        Do0 = Cw ^ ROL32(Cz, 1); \
        Cy  = XOR5(Asi1, Aki1, Abi0, Ami0, Agi0); \
        Do1 = Cy ^ Cx; \
        Cx  = XOR5(Aba0, Ama0, Aga1, Asa1, Aka0); \
        De0 = Cx ^ ROL32(Cy, 1); \
        Cz  = XOR5(Aba1, Ama1, Aga0, Asa0, Aka1); \
        De1 = Cz ^ Cw; \
        Cy  = XOR5(Ago1, Aso0, Ako0, Abo0, Amo1); \
        Di0 = Du0 ^ ROL32(Cy, 1); \
        Cw  = XOR5(Ago0, Aso1, Ako1, Abo1, Amo0); \
        Di1 = Du1^Cw; \
        Du0 = Cw^ROL32(Cz, 1); \
        Du1 = Cy^Cx; \
\
        Ba = (Aba0^Da0); \
        Be = ROL32((Abe0^De0), 22); \
        Bi = ROL32((Abi0^Di1), 22); \
        Bo = ROL32((Abo0^Do1), 11); \
        Bu = ROL32((Abu0^Du0),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba0 = Ba ^ ( Bi & t12); \
        Aba0 ^= *(pRoundConstants++); \
        Abe0 = t12 ^ ( Bi | Bo); \
        Abi0 = Bi  ^ ( Bu & t34); \
        Abo0 = t34 ^ ( Bu | Ba); \
        Abu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Ba = (Aba1^Da1); \
        Be = ROL32((Abe1^De1), 22); \
        Bi = ROL32((Abi1^Di0), 21); \
        Bo = ROL32((Abo1^Do0), 10); \
        Bu = ROL32((Abu1^Du1),  7); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aba1 = Ba ^ ( Bi & t12); \
        Aba1 ^= *(pRoundConstants++); \
        Abe1 = t12 ^ ( Bi | Bo); \
        Abi1 = Bi  ^ ( Bu & t34); \
        Abo1 = t34 ^ ( Bu | Ba); \
        Abu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Aga0^Da1),  2); \
        Bo = ROL32((Age0^De1), 23); \
        Bu = ROL32((Agi0^Di1), 31); \
        Ba = ROL32((Ago0^Do0), 14); \
        Be = ROL32((Agu0^Du0), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga0 = Ba ^ ( Bi & t12); \
        Age0 = t12 ^ ( Bi | Bo); \
        Agi0 = Bi  ^ ( Bu & t34); \
        Ago0 = t34 ^ ( Bu | Ba); \
        Agu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bi = ROL32((Aga1^Da0),  1); \
        Bo = ROL32((Age1^De0), 22); \
        Bu = ROL32((Agi1^Di0), 30); \
        Ba = ROL32((Ago1^Do1), 14); \
        Be = ROL32((Agu1^Du1), 10); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aga1 = Ba ^ ( Bi & t12); \
        Age1 = t12 ^ ( Bi | Bo); \
        Agi1 = Bi  ^ ( Bu & t34); \
        Ago1 = t34 ^ ( Bu | Ba); \
        Agu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Aka0^Da0),  9); \
        Ba = ROL32((Ake0^De1),  1); \
        Be = ROL32((Aki0^Di0),  3); \
        Bi = ROL32((Ako0^Do1), 13); \
        Bo = ROL32((Aku0^Du0),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka0 = Ba ^ ( Bi & t12); \
        Ake0 = t12 ^ ( Bi | Bo); \
        Aki0 = Bi  ^ ( Bu & t34); \
        Ako0 = t34 ^ ( Bu | Ba); \
        Aku0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bu = ROL32((Aka1^Da1),  9); \
        Ba = (Ake1^De0); \
        Be = ROL32((Aki1^Di1),  3); \
        Bi = ROL32((Ako1^Do0), 12); \
        Bo = ROL32((Aku1^Du1),  4); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Aka1 = Ba ^ ( Bi & t12); \
        Ake1 = t12 ^ ( Bi | Bo); \
        Aki1 = Bi  ^ ( Bu & t34); \
        Ako1 = t34 ^ ( Bu | Ba); \
        Aku1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Ama0^Da0), 18); \
        Bi = ROL32((Ame0^De0),  5); \
        Bo = ROL32((Ami0^Di1),  8); \
        Bu = ROL32((Amo0^Do0), 28); \
        Ba = ROL32((Amu0^Du1), 14); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama0 = Ba ^ ( Bi & t12); \
        Ame0 = t12 ^ ( Bi | Bo); \
        Ami0 = Bi  ^ ( Bu & t34); \
        Amo0 = t34 ^ ( Bu | Ba); \
        Amu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Be = ROL32((Ama1^Da1), 18); \
        Bi = ROL32((Ame1^De1),  5); \
        Bo = ROL32((Ami1^Di0),  7); \
        Bu = ROL32((Amo1^Do1), 28); \
        Ba = ROL32((Amu1^Du0), 13); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Ama1 = Ba ^ ( Bi & t12); \
        Ame1 = t12 ^ ( Bi | Bo); \
        Ami1 = Bi  ^ ( Bu & t34); \
        Amo1 = t34 ^ ( Bu | Ba); \
        Amu1 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Asa0^Da1), 21); \
        Bu = ROL32((Ase0^De0),  1); \
        Ba = ROL32((Asi0^Di0), 31); \
        Be = ROL32((Aso0^Do1), 28); \
        Bi = ROL32((Asu0^Du1), 20); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa0 = Ba ^ ( Bi & t12); \
        Ase0 = t12 ^ ( Bi | Bo); \
        Asi0 = Bi  ^ ( Bu & t34); \
        Aso0 = t34 ^ ( Bu | Ba); \
        Asu0 = Bu  ^ ( Be & (Ba ^ Be)); \
        Bo = ROL32((Asa1^Da0), 20); \
        Bu = ROL32((Ase1^De1),  1); \
        Ba = ROL32((Asi1^Di1), 31); \
        Be = ROL32((Aso1^Do0), 27); \
        Bi = ROL32((Asu1^Du0), 19); \
        t12 = Be ^ Bi; t34 = Bo ^ Bu; \
        Asa1 = Ba ^ ( Bi & t12); \
        Ase1 = t12 ^ ( Bi | Bo); \
        Asi1 = Bi  ^ ( Bu & t34); \
        Aso1 = t34 ^ ( Bu | Ba); \
        Asu1 = Bu  ^ ( Be & (Ba ^ Be))

void KeccakP1600_Permute_Nrounds(KeccakP1600_plain32_state *state, unsigned int nRounds)
{
    uint32_t Da0, De0, Di0, Do0, Du0;
    uint32_t Da1, De1, Di1, Do1, Du1;
    uint32_t Ba, Be, Bi, Bo, Bu;
    uint32_t Cx, Cy, Cz, Cw;
    uint32_t t12, t34;
    const uint32_t *pRoundConstants = KeccakF1600RoundConstants_int2+(24-nRounds)*2;
    uint32_t *stateAsHalfLanes = state->A;
    #define Aba0 stateAsHalfLanes[ 0]
    #define Aba1 stateAsHalfLanes[ 1]
    #define Abe0 stateAsHalfLanes[ 2]
    #define Abe1 stateAsHalfLanes[ 3]
    #define Abi0 stateAsHalfLanes[ 4]
    #define Abi1 stateAsHalfLanes[ 5]
    #define Abo0 stateAsHalfLanes[ 6]
    #define Abo1 stateAsHalfLanes[ 7]
    #define Abu0 stateAsHalfLanes[ 8]
    #define Abu1 stateAsHalfLanes[ 9]
    #define Aga0 stateAsHalfLanes[10]
    #define Aga1 stateAsHalfLanes[11]
    #define Age0 stateAsHalfLanes[12]
    #define Age1 stateAsHalfLanes[13]
    #define Agi0 stateAsHalfLanes[14]
    #define Agi1 stateAsHalfLanes[15]
    #define Ago0 stateAsHalfLanes[16]
    #define Ago1 stateAsHalfLanes[17]
    #define Agu0 stateAsHalfLanes[18]
    #define Agu1 stateAsHalfLanes[19]
    #define Aka0 stateAsHalfLanes[20]
    #define Aka1 stateAsHalfLanes[21]
    #define Ake0 stateAsHalfLanes[22]
    #define Ake1 stateAsHalfLanes[23]
    #define Aki0 stateAsHalfLanes[24]
    #define Aki1 stateAsHalfLanes[25]
    #define Ako0 stateAsHalfLanes[26]
    #define Ako1 stateAsHalfLanes[27]
    #define Aku0 stateAsHalfLanes[28]
    #define Aku1 stateAsHalfLanes[29]
    #define Ama0 stateAsHalfLanes[30]
    #define Ama1 stateAsHalfLanes[31]
    #define Ame0 stateAsHalfLanes[32]
    #define Ame1 stateAsHalfLanes[33]
    #define Ami0 stateAsHalfLanes[34]
    #define Ami1 stateAsHalfLanes[35]
    #define Amo0 stateAsHalfLanes[36]
    #define Amo1 stateAsHalfLanes[37]
    #define Amu0 stateAsHalfLanes[38]
    #define Amu1 stateAsHalfLanes[39]
    #define Asa0 stateAsHalfLanes[40]
    #define Asa1 stateAsHalfLanes[41]
    #define Ase0 stateAsHalfLanes[42]
    #define Ase1 stateAsHalfLanes[43]
    #define Asi0 stateAsHalfLanes[44]
    #define Asi1 stateAsHalfLanes[45]
    #define Aso0 stateAsHalfLanes[46]
    #define Aso1 stateAsHalfLanes[47]
    #define Asu0 stateAsHalfLanes[48]
    #define Asu1 stateAsHalfLanes[49]

    nRounds &= 3;
    switch ( nRounds )
    {
        #define I0 Ba
        #define I1 Be
        #define T0 Bi
        #define T1 Bo
        #define SwapPI13( in0,in1,in2,in3,eo0,eo1,eo2,eo3 ) \
            I0 = (in0)[0]; I1 = (in0)[1];       \
            T0 = (in1)[0]; T1 = (in1)[1];       \
            (in0)[eo0] = T0; (in0)[eo0^1] = T1; \
            T0 = (in2)[0]; T1 = (in2)[1];       \
            (in1)[eo1] = T0; (in1)[eo1^1] = T1; \
            T0 = (in3)[0]; T1 = (in3)[1];       \
            (in2)[eo2] = T0; (in2)[eo2^1] = T1; \
            (in3)[eo3] = I0; (in3)[eo3^1] = I1
        #define SwapPI2( in0,in1,in2,in3 ) \
            I0 = (in0)[0]; I1 = (in0)[1]; \
            T0 = (in1)[0]; T1 = (in1)[1]; \
            (in0)[1] = T0; (in0)[0] = T1; \
            (in1)[1] = I0; (in1)[0] = I1; \
            I0 = (in2)[0]; I1 = (in2)[1]; \
            T0 = (in3)[0]; T1 = (in3)[1]; \
            (in2)[1] = T0; (in2)[0] = T1; \
            (in3)[1] = I0; (in3)[0] = I1
        #define SwapEO( even,odd ) T0 = even; even = odd; odd = T0

        case 1:
            SwapPI13( &Aga0, &Aka0, &Asa0, &Ama0, 1, 0, 1, 0 );
            SwapPI13( &Abe0, &Age0, &Ame0, &Ake0, 0, 1, 0, 1 );
            SwapPI13( &Abi0, &Aki0, &Agi0, &Asi0, 1, 0, 1, 0 );
            SwapEO( Ami0, Ami1 );
            SwapPI13( &Abo0, &Amo0, &Aso0, &Ago0, 1, 0, 1, 0 );
            SwapEO( Ako0, Ako1 );
            SwapPI13( &Abu0, &Asu0, &Aku0, &Amu0, 0, 1, 0, 1 );
            break;        

        case 2:
            SwapPI2( &Aga0, &Asa0, &Aka0, &Ama0 );
            SwapPI2( &Abe0, &Ame0, &Age0, &Ake0 );
            SwapPI2( &Abi0, &Agi0, &Aki0, &Asi0 );
            SwapPI2( &Abo0, &Aso0, &Ago0, &Amo0 );
            SwapPI2( &Abu0, &Aku0, &Amu0, &Asu0 );
            break;        

        case 3:
            SwapPI13( &Aga0, &Ama0, &Asa0, &Aka0, 0, 1, 0, 1 );
            SwapPI13( &Abe0, &Ake0, &Ame0, &Age0, 1, 0, 1, 0 );
            SwapPI13( &Abi0, &Asi0, &Agi0, &Aki0, 0, 1, 0, 1 );
            SwapEO( Ami0, Ami1 );
            SwapPI13( &Abo0, &Ago0, &Aso0, &Amo0, 0, 1, 0, 1 );
            SwapEO( Ako0, Ako1 );
            SwapPI13( &Abu0, &Amu0, &Aku0, &Asu0, 1, 0, 1, 0 );
            break;        
        #undef I0
        #undef I1
        #undef T0
        #undef T1
        #undef SwapPI13
        #undef SwapPI2
        #undef SwapEO
    }

    do
    {
        /* Code for 4 rounds, using factor 2 interleaving, 64-bit lanes mapped to 32-bit words */
        switch ( nRounds )
        {
            case 0: KeccakRound0(); /* fall through */
            case 3: KeccakRound1(); /* fall through */
            case 2: KeccakRound2(); /* fall through */
            case 1: KeccakRound3();
        }
        nRounds = 0;
    }
    while ( *pRoundConstants != 0xFF );

    #undef Aba0
    #undef Aba1
    #undef Abe0
    #undef Abe1
    #undef Abi0
    #undef Abi1
    #undef Abo0
    #undef Abo1
    #undef Abu0
    #undef Abu1
    #undef Aga0
    #undef Aga1
    #undef Age0
    #undef Age1
    #undef Agi0
    #undef Agi1
    #undef Ago0
    #undef Ago1
    #undef Agu0
    #undef Agu1
    #undef Aka0
    #undef Aka1
    #undef Ake0
    #undef Ake1
    #undef Aki0
    #undef Aki1
    #undef Ako0
    #undef Ako1
    #undef Aku0
    #undef Aku1
    #undef Ama0
    #undef Ama1
    #undef Ame0
    #undef Ame1
    #undef Ami0
    #undef Ami1
    #undef Amo0
    #undef Amo1
    #undef Amu0
    #undef Amu1
    #undef Asa0
    #undef Asa1
    #undef Ase0
    #undef Ase1
    #undef Asi0
    #undef Asi1
    #undef Aso0
    #undef Aso1
    #undef Asu0
    #undef Asu1
}

/* ---------------------------------------------------------------- */


// Direct permutation - no conversion needed since state is already interleaved
static void KeccakF1600_StatePermute(KeccakP1600_plain32_state* state){
    KeccakP1600_Permute_Nrounds(state, 24);
}






/* ---------------------------------------------------------------- */
/* FIPS202 high-level functions based on XKCP design patterns      */
/* ---------------------------------------------------------------- */

// Absorb with automatic padding - used by all FIPS202 functions
static void keccak_absorb(KeccakP1600_plain32_state *state,
                          unsigned int rate,
                          const uint8_t *input,
                          size_t inputByteLen,
                          uint8_t delimitedSuffix)
{
    KeccakP1600_Initialize(state);

    // Absorb full blocks
    while(inputByteLen >= rate) {
        KeccakP1600_AddBytes(state, input, 0, rate);
        KeccakF1600_StatePermute(state);
        input += rate;
        inputByteLen -= rate;
    }

    // Absorb final partial block
    if (inputByteLen > 0) {
        KeccakP1600_AddBytes(state, input, 0, inputByteLen);
    }

    // Pad with delimited suffix
    KeccakP1600_AddByte(state, delimitedSuffix, inputByteLen);

    // If delimited suffix already has 0x80 bit, we're done with padding
    if ((delimitedSuffix & 0x80) != 0) {
        if (inputByteLen == (rate - 1)) {
            KeccakF1600_StatePermute(state);
        }
    }
    else {
        // Add final 0x80 padding byte
        KeccakP1600_AddByte(state, 0x80, rate - 1);
    }
}

// Squeeze arbitrary bytes from state
static void keccak_squeeze(KeccakP1600_plain32_state *state,
                           unsigned int rate,
                           uint8_t *output,
                           size_t outputByteLen)
{
    size_t blockSize;

    // Extract data in rate-sized blocks
    while(outputByteLen > 0) {
        blockSize = (outputByteLen < rate) ? outputByteLen : rate;
        KeccakF1600_StatePermute(state);
        KeccakP1600_ExtractBytes(state, output, 0, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;
    }
}
/* ---------------------------------------------------------------- */
/* SHAKE128 - XOF with 128-bit security                            */
/* ---------------------------------------------------------------- */

void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
    keccak_absorb(&state->s, SHAKE128_RATE, in, inlen, 0x1F);
    state->pos = SHAKE128_RATE;  // Need to permute before squeezing
}

// Optimized: absorb 32-byte seed + 2 bytes (x, y) without temporary buffer
void shake128_absorb_direct(keccak_state *state,
                            const uint8_t seed[32], uint8_t x, uint8_t y)
{
    KeccakP1600_Initialize(&state->s);

    // Absorb 32-byte seed directly
    KeccakP1600_AddBytes(&state->s, seed, 0, 32);

    // Absorb x at position 32
    KeccakP1600_AddByte(&state->s, x, 32);

    // Absorb y at position 33
    KeccakP1600_AddByte(&state->s, y, 33);

    // Pad: delimited suffix 0x1F at position 34
    KeccakP1600_AddByte(&state->s, 0x1F, 34);

    // Final padding 0x80 at rate-1
    KeccakP1600_AddByte(&state->s, 0x80, SHAKE128_RATE - 1);

    state->pos = SHAKE128_RATE;  // Need to permute before squeezing
}

void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    for(size_t i = 0; i < nblocks; ++i) {
        KeccakF1600_StatePermute(&state->s);
        KeccakP1600_ExtractBytes(&state->s, out, 0, SHAKE128_RATE);
        out += SHAKE128_RATE;
    }
}

/* ---------------------------------------------------------------- */
/* SHAKE256 - XOF with 256-bit security                            */
/* ---------------------------------------------------------------- */

void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
    keccak_absorb(&state->s, SHAKE256_RATE, in, inlen, 0x1F);
    state->pos = SHAKE256_RATE;  // Need to permute before squeezing
}

// Optimized: absorb 32-byte key + 1-byte nonce without temporary buffer
void shake256_prf_direct(uint8_t *out, size_t outlen,
                         const uint8_t key[32], uint8_t nonce)
{
    KeccakP1600_plain32_state s;

    KeccakP1600_Initialize(&s);

    // Absorb 32-byte key directly
    KeccakP1600_AddBytes(&s, key, 0, MLKEM_SYMBYTES);

    // Absorb nonce at position 32
    KeccakP1600_AddByte(&s, nonce, MLKEM_SYMBYTES);

    // Pad: delimited suffix 0x1F at position 33
    KeccakP1600_AddByte(&s, 0x1F, MLKEM_SYMBYTES+1);

    // Final padding 0x80 at rate-1
    KeccakP1600_AddByte(&s, 0x80, SHAKE256_RATE - 1);

    // Squeeze output
    keccak_squeeze(&s, SHAKE256_RATE, out, outlen);
}

void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    for(size_t i = 0; i < nblocks; ++i) {
        KeccakF1600_StatePermute(&state->s);
        KeccakP1600_ExtractBytes(&state->s, out, 0, SHAKE256_RATE);
        out += SHAKE256_RATE;
    }
}

void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    size_t len;

    while(outlen > 0) {
        // Generate new block if needed
        if(state->pos == SHAKE256_RATE) {
            KeccakF1600_StatePermute(&state->s);
            state->pos = 0;
        }

        // Extract available bytes from current block
        len = SHAKE256_RATE - state->pos;
        if(len > outlen) {
            len = outlen;
        }

        KeccakP1600_ExtractBytes(&state->s, out, state->pos, len);
        out += len;
        outlen -= len;
        state->pos += len;
    }
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    KeccakP1600_plain32_state state;

    keccak_absorb(&state, SHAKE256_RATE, in, inlen, 0x1F);
    keccak_squeeze(&state, SHAKE256_RATE, out, outlen);
}

/* ---------------------------------------------------------------- */
/* SHA3 - Fixed-length hash functions                              */
/* ---------------------------------------------------------------- */

void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
    KeccakP1600_plain32_state s;

    keccak_absorb(&s, SHA3_256_RATE, in, inlen, 0x06);
    KeccakF1600_StatePermute(&s);
    KeccakP1600_ExtractBytes(&s, h, 0, 32);
}

void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
    KeccakP1600_plain32_state s;

    keccak_absorb(&s, SHA3_512_RATE, in, inlen, 0x06);
    KeccakF1600_StatePermute(&s);
    KeccakP1600_ExtractBytes(&s, h, 0, 64);
}




