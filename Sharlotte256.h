#ifndef SHARLOTTE256_H
#define SHARLOTTE256_H

#if !defined(__x86_64__) && !defined(__amd64__)
#  error This library is not supported by your platform!
#endif

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sha256 Prototype. Intentionally has the
 * exact same API as OpenSSL.
 * Refer to the Sharlotte256 and AutoSHA256Setter
 * functions for more details.
 */
typedef unsigned char *(*Sharlotte256_func_t)(const unsigned char *, size_t,
					      unsigned char *);

#ifndef DONT_DEFINE_SHA256_FUNC_T
/**
 * Sharlotte256_func_t is meant to be
 * used internally. Use Sha256_func_t.
 */
typedef Sharlotte256_func_t Sha256_func_t;
#endif

/**
 * Function to check if the target machine supports SSE4
 * @return 1 if it supports SSE4, 0 otherwise.
 */
int SSE4Compat(void);

/**
 * The SSE4 Sha256 function.
 * @param data pointer of the char array to be SHA256'd.
 * @param len length of the input to be hashed.
 * @param result pointer of where the result should be put.
 * If NULL, the result will be put in malloc'd space.
 * @return a pointer of where the result was put.
 * especially useful if NULL is provided to result.
 */
unsigned char *Sharlotte256(const unsigned char *data, size_t len,
			    unsigned char *result);

/**
 * Sets the SHA256 function to the SSE4 SHA256, or to
 * the alternativeFunc if the machine doesn't have SSE4.
 * The best choice if you use OpenSSL.
 * @param alternativeFunc the Sha256 function
 * which should run on older machines. Compatible with OpenSSL!
 * @return the best Sha256 function depending on the machine.
 */
Sharlotte256_func_t AutoSHA256Setter(Sharlotte256_func_t alternativeFunc);

#ifdef __cplusplus
}
#endif
#endif  // SHARLOTTE256_H
