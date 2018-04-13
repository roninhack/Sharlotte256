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

#include "Sharlotte256.h"
#include "sha256.cpp"

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

Sharlotte256_func_t AutoSha256Setter(Sharlotte256_func_t alternativeFunc) {
  if (SSE4Compat()) return Sharlotte256;
  return alternativeFunc;
}
