// Copyright (c) 2012, Intel Corporation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the
//   distribution.
//
// * Neither the name of the Intel Corporation nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
//
// THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// The MIT License (MIT)
//
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2009-2018 Bitcoin Developers
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// To format:
// clang-format -i -verbose -style="{BasedOnStyle: Google, UseTab: Always,
// IndentPPDirectives: AfterHash}" Sharlotte256.cpp test.c Sharlotte256.h


#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#  ifdef __GNUC__
#    if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#      define LITTLE_ENDIAN
#    elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#      define BIG_ENDIAN
#    endif  // __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  elif defined(_WIN32)
#    include <Windows.h>
#    if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#      define LITTLE_ENDIAN
#    elif REG_DWORD == REG_DWORD_BIG_ENDIANN
#      define BIG_ENDIAN
#    endif  // REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#  elif defined(__linux__)
#    include <endian.h>
#    define HAS_FUNC
#    if __BYTE_ORDER == __LITTLE_ENDIAN
#      define LITTLE_ENDIAN
#    elif __BYTE_ORDER == __BIG_ENDIAN
#      define BIG_ENDIAN
#    endif
#    include <byteswap.h>
#  endif  // defined(__linux__)
#endif    // !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#  warning Cannot determine endianness! Assuming it is little endian. To ignore\
this, add #define LITTLE_ENDIAN or BIG_ENDIAN, or pass -DLITTLE_ENDIAN or \
-DBIG_ENDIAN to the compiler.
#  define LITTLE_ENDIAN
#endif  // !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)

#include <cpuid.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int SSE4Compat(void) {
  uint32_t eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx >> 19) & 1) {
    return 1;
  }
  return 0;
}

#ifndef HAS_FUNC
#  if defined(__APPLE__)
#    include <libkern/OSByteOrder.h>
#    define bswap_32(x) OSSwapInt32(x)
#    define bswap_64(x) OSSwapInt64(x)
#  else  // defined(__APPLE__)
uint32_t static inline bswap_32(uint32_t x) {
  return (((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >> 8) |
	  ((x & 0x0000ff00U) << 8) | ((x & 0x000000ffU) << 24));
}

uint64_t static inline bswap_64(uint64_t x) {
  return (
      ((x & 0xff00000000000000ull) >> 56) |
      ((x & 0x00ff000000000000ull) >> 40) |
      ((x & 0x0000ff0000000000ull) >> 24) | ((x & 0x000000ff00000000ull) >> 8) |
      ((x & 0x00000000ff000000ull) << 8) | ((x & 0x0000000000ff0000ull) << 24) |
      ((x & 0x000000000000ff00ull) << 40) |
      ((x & 0x00000000000000ffull) << 56));
}
#  endif
#  ifdef LITTLE_ENDIAN
uint32_t static inline htobe32(uint32_t host_32bits) {
  return bswap_32(host_32bits);
}

uint64_t static inline htobe64(uint64_t host_64bits) {
  return bswap_64(host_64bits);
}
#  else
uint32_t static inline htobe32(uint32_t host_32bits) { return host_32bits; }

uint64_t static inline htobe64(uint64_t host_64bits) { return host_64bits; }

#  endif
#endif

void static inline WriteBE32(unsigned char *ptr, uint32_t x) {
  uint32_t v = htobe32(x);
  memcpy(ptr, (char *)&v, 4);
}

void static inline WriteBE64(unsigned char *ptr, uint64_t x) {
  uint64_t v = htobe64(x);
  memcpy(ptr, (char *)&v, 8);
}


static void Transform(uint32_t*, const unsigned char*, size_t);

unsigned char *Sharlotte256(const unsigned char *data, size_t len,
			    unsigned char *result) {
  // clang-format off
  uint32_t s[8] = {
    0x6a09e667ul, 0xbb67ae85ul,
    0x3c6ef372ul, 0xa54ff53aul,
		0x510e527ful, 0x9b05688cul,
    0x1f83d9abul, 0x5be0cd19ul
  };
  // clang-format on
  uint64_t bytes = 0;
  unsigned char buf[64];
  {
    const unsigned char *end = data + len;
    if (len >= 64) {
      size_t blocks = len / 64;
      Transform(s, data, blocks);
      bytes += 64 * blocks;
      data += 64 * blocks;
    }
    if (end > data) {
      // Fill the buffer with what remains.
      memcpy(buf, data, end - data);
      bytes += end - data;
    }
  }
  {
    const unsigned char *pad =
	(const unsigned char *)((const unsigned char[64]){0x80});
    const size_t len = 1 + ((119 - (bytes % 64)) % 64);
    const unsigned char *end = pad + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
      memcpy(buf + bufsize, pad, 64 - bufsize);
      bytes += 64 - bufsize;
      pad += 64 - bufsize;
      Transform(s, buf, 1);
      bufsize = 0;
    }
    // assert(end - pad < 64);
    if (end > pad) {
      memcpy(buf + bufsize, pad, end - pad);
      bytes += end - pad;
    }
  }
  if (result == NULL) result = (unsigned char *)malloc(32 * sizeof(char));
  {
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, len << 3);
    // Write(sizedesc, 8);
    size_t bufsize = bytes % 64;
    memcpy(buf + bufsize, sizedesc, 64 - bufsize);
    Transform(s, buf, 1);
    // assert(end - sizedesc < 64);
  }
  WriteBE32(result, s[0]);
  WriteBE32(result + 4, s[1]);
  WriteBE32(result + 8, s[2]);
  WriteBE32(result + 12, s[3]);
  WriteBE32(result + 16, s[4]);
  WriteBE32(result + 20, s[5]);
  WriteBE32(result + 24, s[6]);
  WriteBE32(result + 28, s[7]);
  return result;
}

typedef unsigned char *(*Sharlotte256_func_t)(const unsigned char *, size_t,
					      unsigned char *);

Sharlotte256_func_t AutoSHA256Setter(Sharlotte256_func_t alternativeFunc) {
  if (SSE4Compat()) return Sharlotte256;
  return alternativeFunc;
}

static void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks) {
  static const uint32_t K256 alignas(16)[] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  };
  static const uint32_t FLIP_MASK alignas(16)[] = {0x00010203, 0x04050607,
						   0x08090a0b, 0x0c0d0e0f};
  static const uint32_t SHUF_00BA alignas(16)[] = {0x03020100, 0x0b0a0908,
						   0xffffffff, 0xffffffff};
  static const uint32_t SHUF_DC00 alignas(16)[] = {0xffffffff, 0xffffffff,
						   0x03020100, 0x0b0a0908};
  uint32_t a, b, c, d, f, g, h, y0, y1, y2;
  uint64_t tbl;
  uint64_t inp_end, inp;
  uint32_t xfer alignas(16)[4];

  __asm__ __volatile__(
      "shl    $0x6,%2;"
      "je     Ldone_hash_%=;"
      "add    %1,%2;"
      "mov    %2,%14;"
      "mov    (%0),%3;"
      "mov    0x4(%0),%4;"
      "mov    0x8(%0),%5;"
      "mov    0xc(%0),%6;"
      "mov    0x10(%0),%k2;"
      "mov    0x14(%0),%7;"
      "mov    0x18(%0),%8;"
      "mov    0x1c(%0),%9;"
      "movdqa %18,%%xmm12;"
      "movdqa %19,%%xmm10;"
      "movdqa %20,%%xmm11;"

      "Lloop0_%=:"
      "lea    %17,%13;"
      "movdqu (%1),%%xmm4;"
      "pshufb %%xmm12,%%xmm4;"
      "movdqu 0x10(%1),%%xmm5;"
      "pshufb %%xmm12,%%xmm5;"
      "movdqu 0x20(%1),%%xmm6;"
      "pshufb %%xmm12,%%xmm6;"
      "movdqu 0x30(%1),%%xmm7;"
      "pshufb %%xmm12,%%xmm7;"
      "mov    %1,%15;"
      "mov    $3,%1;"

      "Lloop1_%=:"
      "movdqa 0x0(%13),%%xmm9;"
      "paddd  %%xmm4,%%xmm9;"
      "movdqa %%xmm9,%16;"
      "movdqa %%xmm7,%%xmm0;"
      "mov    %k2,%10;"
      "ror    $0xe,%10;"
      "mov    %3,%11;"
      "palignr $0x4,%%xmm6,%%xmm0;"
      "ror    $0x9,%11;"
      "xor    %k2,%10;"
      "mov    %7,%12;"
      "ror    $0x5,%10;"
      "movdqa %%xmm5,%%xmm1;"
      "xor    %3,%11;"
      "xor    %8,%12;"
      "paddd  %%xmm4,%%xmm0;"
      "xor    %k2,%10;"
      "and    %k2,%12;"
      "ror    $0xb,%11;"
      "palignr $0x4,%%xmm4,%%xmm1;"
      "xor    %3,%11;"
      "ror    $0x6,%10;"
      "xor    %8,%12;"
      "movdqa %%xmm1,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    %16,%12;"
      "movdqa %%xmm1,%%xmm3;"
      "mov    %3,%10;"
      "add    %12,%9;"
      "mov    %3,%12;"
      "pslld  $0x19,%%xmm1;"
      "or     %5,%10;"
      "add    %9,%6;"
      "and    %5,%12;"
      "psrld  $0x7,%%xmm2;"
      "and    %4,%10;"
      "add    %11,%9;"
      "por    %%xmm2,%%xmm1;"
      "or     %12,%10;"
      "add    %10,%9;"
      "movdqa %%xmm3,%%xmm2;"
      "mov    %6,%10;"
      "mov    %9,%11;"
      "movdqa %%xmm3,%%xmm8;"
      "ror    $0xe,%10;"
      "xor    %6,%10;"
      "mov    %k2,%12;"
      "ror    $0x9,%11;"
      "pslld  $0xe,%%xmm3;"
      "xor    %9,%11;"
      "ror    $0x5,%10;"
      "xor    %7,%12;"
      "psrld  $0x12,%%xmm2;"
      "ror    $0xb,%11;"
      "xor    %6,%10;"
      "and    %6,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm1;"
      "xor    %9,%11;"
      "xor    %7,%12;"
      "psrld  $0x3,%%xmm8;"
      "add    %10,%12;"
      "add    4+%16,%12;"
      "ror    $0x2,%11;"
      "pxor   %%xmm2,%%xmm1;"
      "mov    %9,%10;"
      "add    %12,%8;"
      "mov    %9,%12;"
      "pxor   %%xmm8,%%xmm1;"
      "or     %4,%10;"
      "add    %8,%5;"
      "and    %4,%12;"
      "pshufd $0xfa,%%xmm7,%%xmm2;"
      "and    %3,%10;"
      "add    %11,%8;"
      "paddd  %%xmm1,%%xmm0;"
      "or     %12,%10;"
      "add    %10,%8;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %5,%10;"
      "mov    %8,%11;"
      "ror    $0xe,%10;"
      "movdqa %%xmm2,%%xmm8;"
      "xor    %5,%10;"
      "ror    $0x9,%11;"
      "mov    %6,%12;"
      "xor    %8,%11;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %k2,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %5,%10;"
      "and    %5,%12;"
      "psrld  $0xa,%%xmm8;"
      "ror    $0xb,%11;"
      "xor    %8,%11;"
      "xor    %k2,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm2;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    8+%16,%12;"
      "pxor   %%xmm2,%%xmm8;"
      "mov    %8,%10;"
      "add    %12,%7;"
      "mov    %8,%12;"
      "pshufb %%xmm10,%%xmm8;"
      "or     %3,%10;"
      "add    %7,%4;"
      "and    %3,%12;"
      "paddd  %%xmm8,%%xmm0;"
      "and    %9,%10;"
      "add    %11,%7;"
      "pshufd $0x50,%%xmm0,%%xmm2;"
      "or     %12,%10;"
      "add    %10,%7;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %4,%10;"
      "ror    $0xe,%10;"
      "mov    %7,%11;"
      "movdqa %%xmm2,%%xmm4;"
      "ror    $0x9,%11;"
      "xor    %4,%10;"
      "mov    %5,%12;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %7,%11;"
      "xor    %6,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %4,%10;"
      "and    %4,%12;"
      "ror    $0xb,%11;"
      "psrld  $0xa,%%xmm4;"
      "xor    %7,%11;"
      "ror    $0x6,%10;"
      "xor    %6,%12;"
      "pxor   %%xmm3,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    12+%16,%12;"
      "pxor   %%xmm2,%%xmm4;"
      "mov    %7,%10;"
      "add    %12,%k2;"
      "mov    %7,%12;"
      "pshufb %%xmm11,%%xmm4;"
      "or     %9,%10;"
      "add    %k2,%3;"
      "and    %9,%12;"
      "paddd  %%xmm0,%%xmm4;"
      "and    %8,%10;"
      "add    %11,%k2;"
      "or     %12,%10;"
      "add    %10,%k2;"
      "movdqa 0x10(%13),%%xmm9;"
      "paddd  %%xmm5,%%xmm9;"
      "movdqa %%xmm9,%16;"
      "movdqa %%xmm4,%%xmm0;"
      "mov    %3,%10;"
      "ror    $0xe,%10;"
      "mov    %k2,%11;"
      "palignr $0x4,%%xmm7,%%xmm0;"
      "ror    $0x9,%11;"
      "xor    %3,%10;"
      "mov    %4,%12;"
      "ror    $0x5,%10;"
      "movdqa %%xmm6,%%xmm1;"
      "xor    %k2,%11;"
      "xor    %5,%12;"
      "paddd  %%xmm5,%%xmm0;"
      "xor    %3,%10;"
      "and    %3,%12;"
      "ror    $0xb,%11;"
      "palignr $0x4,%%xmm5,%%xmm1;"
      "xor    %k2,%11;"
      "ror    $0x6,%10;"
      "xor    %5,%12;"
      "movdqa %%xmm1,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    %16,%12;"
      "movdqa %%xmm1,%%xmm3;"
      "mov    %k2,%10;"
      "add    %12,%6;"
      "mov    %k2,%12;"
      "pslld  $0x19,%%xmm1;"
      "or     %8,%10;"
      "add    %6,%9;"
      "and    %8,%12;"
      "psrld  $0x7,%%xmm2;"
      "and    %7,%10;"
      "add    %11,%6;"
      "por    %%xmm2,%%xmm1;"
      "or     %12,%10;"
      "add    %10,%6;"
      "movdqa %%xmm3,%%xmm2;"
      "mov    %9,%10;"
      "mov    %6,%11;"
      "movdqa %%xmm3,%%xmm8;"
      "ror    $0xe,%10;"
      "xor    %9,%10;"
      "mov    %3,%12;"
      "ror    $0x9,%11;"
      "pslld  $0xe,%%xmm3;"
      "xor    %6,%11;"
      "ror    $0x5,%10;"
      "xor    %4,%12;"
      "psrld  $0x12,%%xmm2;"
      "ror    $0xb,%11;"
      "xor    %9,%10;"
      "and    %9,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm1;"
      "xor    %6,%11;"
      "xor    %4,%12;"
      "psrld  $0x3,%%xmm8;"
      "add    %10,%12;"
      "add    4+%16,%12;"
      "ror    $0x2,%11;"
      "pxor   %%xmm2,%%xmm1;"
      "mov    %6,%10;"
      "add    %12,%5;"
      "mov    %6,%12;"
      "pxor   %%xmm8,%%xmm1;"
      "or     %7,%10;"
      "add    %5,%8;"
      "and    %7,%12;"
      "pshufd $0xfa,%%xmm4,%%xmm2;"
      "and    %k2,%10;"
      "add    %11,%5;"
      "paddd  %%xmm1,%%xmm0;"
      "or     %12,%10;"
      "add    %10,%5;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %8,%10;"
      "mov    %5,%11;"
      "ror    $0xe,%10;"
      "movdqa %%xmm2,%%xmm8;"
      "xor    %8,%10;"
      "ror    $0x9,%11;"
      "mov    %9,%12;"
      "xor    %5,%11;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %3,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %8,%10;"
      "and    %8,%12;"
      "psrld  $0xa,%%xmm8;"
      "ror    $0xb,%11;"
      "xor    %5,%11;"
      "xor    %3,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm2;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    8+%16,%12;"
      "pxor   %%xmm2,%%xmm8;"
      "mov    %5,%10;"
      "add    %12,%4;"
      "mov    %5,%12;"
      "pshufb %%xmm10,%%xmm8;"
      "or     %k2,%10;"
      "add    %4,%7;"
      "and    %k2,%12;"
      "paddd  %%xmm8,%%xmm0;"
      "and    %6,%10;"
      "add    %11,%4;"
      "pshufd $0x50,%%xmm0,%%xmm2;"
      "or     %12,%10;"
      "add    %10,%4;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %7,%10;"
      "ror    $0xe,%10;"
      "mov    %4,%11;"
      "movdqa %%xmm2,%%xmm5;"
      "ror    $0x9,%11;"
      "xor    %7,%10;"
      "mov    %8,%12;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %4,%11;"
      "xor    %9,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %7,%10;"
      "and    %7,%12;"
      "ror    $0xb,%11;"
      "psrld  $0xa,%%xmm5;"
      "xor    %4,%11;"
      "ror    $0x6,%10;"
      "xor    %9,%12;"
      "pxor   %%xmm3,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    12+%16,%12;"
      "pxor   %%xmm2,%%xmm5;"
      "mov    %4,%10;"
      "add    %12,%3;"
      "mov    %4,%12;"
      "pshufb %%xmm11,%%xmm5;"
      "or     %6,%10;"
      "add    %3,%k2;"
      "and    %6,%12;"
      "paddd  %%xmm0,%%xmm5;"
      "and    %5,%10;"
      "add    %11,%3;"
      "or     %12,%10;"
      "add    %10,%3;"
      "movdqa 0x20(%13),%%xmm9;"
      "paddd  %%xmm6,%%xmm9;"
      "movdqa %%xmm9,%16;"
      "movdqa %%xmm5,%%xmm0;"
      "mov    %k2,%10;"
      "ror    $0xe,%10;"
      "mov    %3,%11;"
      "palignr $0x4,%%xmm4,%%xmm0;"
      "ror    $0x9,%11;"
      "xor    %k2,%10;"
      "mov    %7,%12;"
      "ror    $0x5,%10;"
      "movdqa %%xmm7,%%xmm1;"
      "xor    %3,%11;"
      "xor    %8,%12;"
      "paddd  %%xmm6,%%xmm0;"
      "xor    %k2,%10;"
      "and    %k2,%12;"
      "ror    $0xb,%11;"
      "palignr $0x4,%%xmm6,%%xmm1;"
      "xor    %3,%11;"
      "ror    $0x6,%10;"
      "xor    %8,%12;"
      "movdqa %%xmm1,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    %16,%12;"
      "movdqa %%xmm1,%%xmm3;"
      "mov    %3,%10;"
      "add    %12,%9;"
      "mov    %3,%12;"
      "pslld  $0x19,%%xmm1;"
      "or     %5,%10;"
      "add    %9,%6;"
      "and    %5,%12;"
      "psrld  $0x7,%%xmm2;"
      "and    %4,%10;"
      "add    %11,%9;"
      "por    %%xmm2,%%xmm1;"
      "or     %12,%10;"
      "add    %10,%9;"
      "movdqa %%xmm3,%%xmm2;"
      "mov    %6,%10;"
      "mov    %9,%11;"
      "movdqa %%xmm3,%%xmm8;"
      "ror    $0xe,%10;"
      "xor    %6,%10;"
      "mov    %k2,%12;"
      "ror    $0x9,%11;"
      "pslld  $0xe,%%xmm3;"
      "xor    %9,%11;"
      "ror    $0x5,%10;"
      "xor    %7,%12;"
      "psrld  $0x12,%%xmm2;"
      "ror    $0xb,%11;"
      "xor    %6,%10;"
      "and    %6,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm1;"
      "xor    %9,%11;"
      "xor    %7,%12;"
      "psrld  $0x3,%%xmm8;"
      "add    %10,%12;"
      "add    4+%16,%12;"
      "ror    $0x2,%11;"
      "pxor   %%xmm2,%%xmm1;"
      "mov    %9,%10;"
      "add    %12,%8;"
      "mov    %9,%12;"
      "pxor   %%xmm8,%%xmm1;"
      "or     %4,%10;"
      "add    %8,%5;"
      "and    %4,%12;"
      "pshufd $0xfa,%%xmm5,%%xmm2;"
      "and    %3,%10;"
      "add    %11,%8;"
      "paddd  %%xmm1,%%xmm0;"
      "or     %12,%10;"
      "add    %10,%8;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %5,%10;"
      "mov    %8,%11;"
      "ror    $0xe,%10;"
      "movdqa %%xmm2,%%xmm8;"
      "xor    %5,%10;"
      "ror    $0x9,%11;"
      "mov    %6,%12;"
      "xor    %8,%11;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %k2,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %5,%10;"
      "and    %5,%12;"
      "psrld  $0xa,%%xmm8;"
      "ror    $0xb,%11;"
      "xor    %8,%11;"
      "xor    %k2,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm2;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    8+%16,%12;"
      "pxor   %%xmm2,%%xmm8;"
      "mov    %8,%10;"
      "add    %12,%7;"
      "mov    %8,%12;"
      "pshufb %%xmm10,%%xmm8;"
      "or     %3,%10;"
      "add    %7,%4;"
      "and    %3,%12;"
      "paddd  %%xmm8,%%xmm0;"
      "and    %9,%10;"
      "add    %11,%7;"
      "pshufd $0x50,%%xmm0,%%xmm2;"
      "or     %12,%10;"
      "add    %10,%7;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %4,%10;"
      "ror    $0xe,%10;"
      "mov    %7,%11;"
      "movdqa %%xmm2,%%xmm6;"
      "ror    $0x9,%11;"
      "xor    %4,%10;"
      "mov    %5,%12;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %7,%11;"
      "xor    %6,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %4,%10;"
      "and    %4,%12;"
      "ror    $0xb,%11;"
      "psrld  $0xa,%%xmm6;"
      "xor    %7,%11;"
      "ror    $0x6,%10;"
      "xor    %6,%12;"
      "pxor   %%xmm3,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    12+%16,%12;"
      "pxor   %%xmm2,%%xmm6;"
      "mov    %7,%10;"
      "add    %12,%k2;"
      "mov    %7,%12;"
      "pshufb %%xmm11,%%xmm6;"
      "or     %9,%10;"
      "add    %k2,%3;"
      "and    %9,%12;"
      "paddd  %%xmm0,%%xmm6;"
      "and    %8,%10;"
      "add    %11,%k2;"
      "or     %12,%10;"
      "add    %10,%k2;"
      "movdqa 0x30(%13),%%xmm9;"
      "paddd  %%xmm7,%%xmm9;"
      "movdqa %%xmm9,%16;"
      "add    $0x40,%13;"
      "movdqa %%xmm6,%%xmm0;"
      "mov    %3,%10;"
      "ror    $0xe,%10;"
      "mov    %k2,%11;"
      "palignr $0x4,%%xmm5,%%xmm0;"
      "ror    $0x9,%11;"
      "xor    %3,%10;"
      "mov    %4,%12;"
      "ror    $0x5,%10;"
      "movdqa %%xmm4,%%xmm1;"
      "xor    %k2,%11;"
      "xor    %5,%12;"
      "paddd  %%xmm7,%%xmm0;"
      "xor    %3,%10;"
      "and    %3,%12;"
      "ror    $0xb,%11;"
      "palignr $0x4,%%xmm7,%%xmm1;"
      "xor    %k2,%11;"
      "ror    $0x6,%10;"
      "xor    %5,%12;"
      "movdqa %%xmm1,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    %16,%12;"
      "movdqa %%xmm1,%%xmm3;"
      "mov    %k2,%10;"
      "add    %12,%6;"
      "mov    %k2,%12;"
      "pslld  $0x19,%%xmm1;"
      "or     %8,%10;"
      "add    %6,%9;"
      "and    %8,%12;"
      "psrld  $0x7,%%xmm2;"
      "and    %7,%10;"
      "add    %11,%6;"
      "por    %%xmm2,%%xmm1;"
      "or     %12,%10;"
      "add    %10,%6;"
      "movdqa %%xmm3,%%xmm2;"
      "mov    %9,%10;"
      "mov    %6,%11;"
      "movdqa %%xmm3,%%xmm8;"
      "ror    $0xe,%10;"
      "xor    %9,%10;"
      "mov    %3,%12;"
      "ror    $0x9,%11;"
      "pslld  $0xe,%%xmm3;"
      "xor    %6,%11;"
      "ror    $0x5,%10;"
      "xor    %4,%12;"
      "psrld  $0x12,%%xmm2;"
      "ror    $0xb,%11;"
      "xor    %9,%10;"
      "and    %9,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm1;"
      "xor    %6,%11;"
      "xor    %4,%12;"
      "psrld  $0x3,%%xmm8;"
      "add    %10,%12;"
      "add    4+%16,%12;"
      "ror    $0x2,%11;"
      "pxor   %%xmm2,%%xmm1;"
      "mov    %6,%10;"
      "add    %12,%5;"
      "mov    %6,%12;"
      "pxor   %%xmm8,%%xmm1;"
      "or     %7,%10;"
      "add    %5,%8;"
      "and    %7,%12;"
      "pshufd $0xfa,%%xmm6,%%xmm2;"
      "and    %k2,%10;"
      "add    %11,%5;"
      "paddd  %%xmm1,%%xmm0;"
      "or     %12,%10;"
      "add    %10,%5;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %8,%10;"
      "mov    %5,%11;"
      "ror    $0xe,%10;"
      "movdqa %%xmm2,%%xmm8;"
      "xor    %8,%10;"
      "ror    $0x9,%11;"
      "mov    %9,%12;"
      "xor    %5,%11;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %3,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %8,%10;"
      "and    %8,%12;"
      "psrld  $0xa,%%xmm8;"
      "ror    $0xb,%11;"
      "xor    %5,%11;"
      "xor    %3,%12;"
      "ror    $0x6,%10;"
      "pxor   %%xmm3,%%xmm2;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    8+%16,%12;"
      "pxor   %%xmm2,%%xmm8;"
      "mov    %5,%10;"
      "add    %12,%4;"
      "mov    %5,%12;"
      "pshufb %%xmm10,%%xmm8;"
      "or     %k2,%10;"
      "add    %4,%7;"
      "and    %k2,%12;"
      "paddd  %%xmm8,%%xmm0;"
      "and    %6,%10;"
      "add    %11,%4;"
      "pshufd $0x50,%%xmm0,%%xmm2;"
      "or     %12,%10;"
      "add    %10,%4;"
      "movdqa %%xmm2,%%xmm3;"
      "mov    %7,%10;"
      "ror    $0xe,%10;"
      "mov    %4,%11;"
      "movdqa %%xmm2,%%xmm7;"
      "ror    $0x9,%11;"
      "xor    %7,%10;"
      "mov    %8,%12;"
      "ror    $0x5,%10;"
      "psrlq  $0x11,%%xmm2;"
      "xor    %4,%11;"
      "xor    %9,%12;"
      "psrlq  $0x13,%%xmm3;"
      "xor    %7,%10;"
      "and    %7,%12;"
      "ror    $0xb,%11;"
      "psrld  $0xa,%%xmm7;"
      "xor    %4,%11;"
      "ror    $0x6,%10;"
      "xor    %9,%12;"
      "pxor   %%xmm3,%%xmm2;"
      "ror    $0x2,%11;"
      "add    %10,%12;"
      "add    12+%16,%12;"
      "pxor   %%xmm2,%%xmm7;"
      "mov    %4,%10;"
      "add    %12,%3;"
      "mov    %4,%12;"
      "pshufb %%xmm11,%%xmm7;"
      "or     %6,%10;"
      "add    %3,%k2;"
      "and    %6,%12;"
      "paddd  %%xmm0,%%xmm7;"
      "and    %5,%10;"
      "add    %11,%3;"
      "or     %12,%10;"
      "add    %10,%3;"
      "sub    $0x1,%1;"
      "jne    Lloop1_%=;"
      "mov    $0x2,%1;"

      "Lloop2_%=:"
      "paddd  0x0(%13),%%xmm4;"
      "movdqa %%xmm4,%16;"
      "mov    %k2,%10;"
      "ror    $0xe,%10;"
      "mov    %3,%11;"
      "xor    %k2,%10;"
      "ror    $0x9,%11;"
      "mov    %7,%12;"
      "xor    %3,%11;"
      "ror    $0x5,%10;"
      "xor    %8,%12;"
      "xor    %k2,%10;"
      "ror    $0xb,%11;"
      "and    %k2,%12;"
      "xor    %3,%11;"
      "ror    $0x6,%10;"
      "xor    %8,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    %16,%12;"
      "mov    %3,%10;"
      "add    %12,%9;"
      "mov    %3,%12;"
      "or     %5,%10;"
      "add    %9,%6;"
      "and    %5,%12;"
      "and    %4,%10;"
      "add    %11,%9;"
      "or     %12,%10;"
      "add    %10,%9;"
      "mov    %6,%10;"
      "ror    $0xe,%10;"
      "mov    %9,%11;"
      "xor    %6,%10;"
      "ror    $0x9,%11;"
      "mov    %k2,%12;"
      "xor    %9,%11;"
      "ror    $0x5,%10;"
      "xor    %7,%12;"
      "xor    %6,%10;"
      "ror    $0xb,%11;"
      "and    %6,%12;"
      "xor    %9,%11;"
      "ror    $0x6,%10;"
      "xor    %7,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    4+%16,%12;"
      "mov    %9,%10;"
      "add    %12,%8;"
      "mov    %9,%12;"
      "or     %4,%10;"
      "add    %8,%5;"
      "and    %4,%12;"
      "and    %3,%10;"
      "add    %11,%8;"
      "or     %12,%10;"
      "add    %10,%8;"
      "mov    %5,%10;"
      "ror    $0xe,%10;"
      "mov    %8,%11;"
      "xor    %5,%10;"
      "ror    $0x9,%11;"
      "mov    %6,%12;"
      "xor    %8,%11;"
      "ror    $0x5,%10;"
      "xor    %k2,%12;"
      "xor    %5,%10;"
      "ror    $0xb,%11;"
      "and    %5,%12;"
      "xor    %8,%11;"
      "ror    $0x6,%10;"
      "xor    %k2,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    8+%16,%12;"
      "mov    %8,%10;"
      "add    %12,%7;"
      "mov    %8,%12;"
      "or     %3,%10;"
      "add    %7,%4;"
      "and    %3,%12;"
      "and    %9,%10;"
      "add    %11,%7;"
      "or     %12,%10;"
      "add    %10,%7;"
      "mov    %4,%10;"
      "ror    $0xe,%10;"
      "mov    %7,%11;"
      "xor    %4,%10;"
      "ror    $0x9,%11;"
      "mov    %5,%12;"
      "xor    %7,%11;"
      "ror    $0x5,%10;"
      "xor    %6,%12;"
      "xor    %4,%10;"
      "ror    $0xb,%11;"
      "and    %4,%12;"
      "xor    %7,%11;"
      "ror    $0x6,%10;"
      "xor    %6,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    12+%16,%12;"
      "mov    %7,%10;"
      "add    %12,%k2;"
      "mov    %7,%12;"
      "or     %9,%10;"
      "add    %k2,%3;"
      "and    %9,%12;"
      "and    %8,%10;"
      "add    %11,%k2;"
      "or     %12,%10;"
      "add    %10,%k2;"
      "paddd  0x10(%13),%%xmm5;"
      "movdqa %%xmm5,%16;"
      "add    $0x20,%13;"
      "mov    %3,%10;"
      "ror    $0xe,%10;"
      "mov    %k2,%11;"
      "xor    %3,%10;"
      "ror    $0x9,%11;"
      "mov    %4,%12;"
      "xor    %k2,%11;"
      "ror    $0x5,%10;"
      "xor    %5,%12;"
      "xor    %3,%10;"
      "ror    $0xb,%11;"
      "and    %3,%12;"
      "xor    %k2,%11;"
      "ror    $0x6,%10;"
      "xor    %5,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    %16,%12;"
      "mov    %k2,%10;"
      "add    %12,%6;"
      "mov    %k2,%12;"
      "or     %8,%10;"
      "add    %6,%9;"
      "and    %8,%12;"
      "and    %7,%10;"
      "add    %11,%6;"
      "or     %12,%10;"
      "add    %10,%6;"
      "mov    %9,%10;"
      "ror    $0xe,%10;"
      "mov    %6,%11;"
      "xor    %9,%10;"
      "ror    $0x9,%11;"
      "mov    %3,%12;"
      "xor    %6,%11;"
      "ror    $0x5,%10;"
      "xor    %4,%12;"
      "xor    %9,%10;"
      "ror    $0xb,%11;"
      "and    %9,%12;"
      "xor    %6,%11;"
      "ror    $0x6,%10;"
      "xor    %4,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    4+%16,%12;"
      "mov    %6,%10;"
      "add    %12,%5;"
      "mov    %6,%12;"
      "or     %7,%10;"
      "add    %5,%8;"
      "and    %7,%12;"
      "and    %k2,%10;"
      "add    %11,%5;"
      "or     %12,%10;"
      "add    %10,%5;"
      "mov    %8,%10;"
      "ror    $0xe,%10;"
      "mov    %5,%11;"
      "xor    %8,%10;"
      "ror    $0x9,%11;"
      "mov    %9,%12;"
      "xor    %5,%11;"
      "ror    $0x5,%10;"
      "xor    %3,%12;"
      "xor    %8,%10;"
      "ror    $0xb,%11;"
      "and    %8,%12;"
      "xor    %5,%11;"
      "ror    $0x6,%10;"
      "xor    %3,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    8+%16,%12;"
      "mov    %5,%10;"
      "add    %12,%4;"
      "mov    %5,%12;"
      "or     %k2,%10;"
      "add    %4,%7;"
      "and    %k2,%12;"
      "and    %6,%10;"
      "add    %11,%4;"
      "or     %12,%10;"
      "add    %10,%4;"
      "mov    %7,%10;"
      "ror    $0xe,%10;"
      "mov    %4,%11;"
      "xor    %7,%10;"
      "ror    $0x9,%11;"
      "mov    %8,%12;"
      "xor    %4,%11;"
      "ror    $0x5,%10;"
      "xor    %9,%12;"
      "xor    %7,%10;"
      "ror    $0xb,%11;"
      "and    %7,%12;"
      "xor    %4,%11;"
      "ror    $0x6,%10;"
      "xor    %9,%12;"
      "add    %10,%12;"
      "ror    $0x2,%11;"
      "add    12+%16,%12;"
      "mov    %4,%10;"
      "add    %12,%3;"
      "mov    %4,%12;"
      "or     %6,%10;"
      "add    %3,%k2;"
      "and    %6,%12;"
      "and    %5,%10;"
      "add    %11,%3;"
      "or     %12,%10;"
      "add    %10,%3;"
      "movdqa %%xmm6,%%xmm4;"
      "movdqa %%xmm7,%%xmm5;"
      "sub    $0x1,%1;"
      "jne    Lloop2_%=;"
      "add    (%0),%3;"
      "mov    %3,(%0);"
      "add    0x4(%0),%4;"
      "mov    %4,0x4(%0);"
      "add    0x8(%0),%5;"
      "mov    %5,0x8(%0);"
      "add    0xc(%0),%6;"
      "mov    %6,0xc(%0);"
      "add    0x10(%0),%k2;"
      "mov    %k2,0x10(%0);"
      "add    0x14(%0),%7;"
      "mov    %7,0x14(%0);"
      "add    0x18(%0),%8;"
      "mov    %8,0x18(%0);"
      "add    0x1c(%0),%9;"
      "mov    %9,0x1c(%0);"
      "mov    %15,%1;"
      "add    $0x40,%1;"
      "cmp    %14,%1;"
      "jne    Lloop0_%=;"

      "Ldone_hash_%=:"

      : "+r"(s), "+r"(chunk), "+r"(blocks), "=r"(a), "=r"(b), "=r"(c), "=r"(d),
	/* e = chunk */ "=r"(f), "=r"(g), "=r"(h), "=r"(y0), "=r"(y1), "=r"(y2),
	"=r"(tbl), "+m"(inp_end), "+m"(inp), "+m"(xfer)
      : "m"(K256), "m"(FLIP_MASK), "m"(SHUF_00BA), "m"(SHUF_DC00)
      : "cc", "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
	"xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12");
}
