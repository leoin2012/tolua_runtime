
/**
 * `b64.h' - b64
 * fast base64 that support custom alphabet 
 * copyright (c) 2019 shuchangliu
 */

#ifndef B64_H
#define B64_H 1

/**
 *  Memory allocation functions to use. You can define b64_malloc and
 * b64_realloc to custom functions if you want.
 */

#ifndef b64_malloc
#  define b64_malloc(ptr) malloc(ptr)
#endif
#ifndef b64_realloc
#  define b64_realloc(ptr, size) realloc(ptr, size)
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Setup custom base64 alphabet
 */
	void b64_setup(unsigned char *);

/**
 * Encode `unsigned char *' source with `size_t' size.
 * Returns a `char *' base64 encoded string.
 */
	char *
	b64_encode (const unsigned char *, size_t);

/**
 * Dencode `char *' source with `size_t' size.
 * Returns a `unsigned char *' base64 decoded string.
 */
	unsigned char *
	b64_decode (const char *, size_t);

/**
 * Dencode `char *' source with `size_t' size.
 * Returns a `unsigned char *' base64 decoded string + size of decoded string.
 */
	unsigned char *
	b64_decode_ex (const char *, size_t, size_t *);

#ifdef __cplusplus
}
#endif

#endif
