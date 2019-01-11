
/**
 * `b64.c' - b64
 *
 * copyright (c) 2014 joseph werle
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "b64.h"

#ifdef b64_USE_CUSTOM_MALLOC
extern void* b64_malloc(size_t);
#endif

#ifdef b64_USE_CUSTOM_REALLOC
extern void* b64_realloc(void*, size_t);
#endif

/*-------------------------------------------------------------------------*\
* Base64 globals
\*-------------------------------------------------------------------------*/
static unsigned char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static unsigned char unb64_table[256];


/*-------------------------------------------------------------------------*\
* Fill base64 decode map.
\*-------------------------------------------------------------------------*/
void b64_setup(unsigned char *b64_string)
{
    strcpy(b64_table, b64_string);
    int i;
    for (i = 0; i <= 255; i++) unb64_table[i] = (unsigned char) 255;
    for (i = 0; i < 64; i++) unb64_table[b64_table[i]] = (unsigned char) i;
    unb64_table['='] = 0;
}

char *
b64_encode (const unsigned char *src, size_t len) {
  int i = 0;
  int j = 0;
  char *enc = NULL;
  size_t size = 0;
  unsigned char buf[4];
  unsigned char tmp[3];

  // alloc
  enc = (char *) b64_malloc(1);
  if (NULL == enc) { return NULL; }

  // parse until end of source
  while (len--) {
    // read up to 3 bytes at a time into `tmp'
    tmp[i++] = *(src++);

    // if 3 bytes read then encode into `buf'
    if (3 == i) {
      buf[0] = (tmp[0] & 0xfc) >> 2;
      buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
      buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
      buf[3] = tmp[2] & 0x3f;

      // allocate 4 new byts for `enc` and
      // then translate each encoded buffer
      // part by index from the base 64 index table
      // into `enc' unsigned char array
      enc = (char *) b64_realloc(enc, size + 4);
      for (i = 0; i < 4; ++i) {
        enc[size++] = b64_table[buf[i]];
      }

      // reset index
      i = 0;
    }
  }

  // remainder
  if (i > 0) {
    // fill `tmp' with `\0' at most 3 times
    for (j = i; j < 3; ++j) {
      tmp[j] = '\0';
    }

    // perform same codec as above
    buf[0] = (tmp[0] & 0xfc) >> 2;
    buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
    buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
    buf[3] = tmp[2] & 0x3f;

    // perform same write to `enc` with new allocation
    for (j = 0; (j < i + 1); ++j) {
      enc = (char *) b64_realloc(enc, size + 1);
      enc[size++] = b64_table[buf[j]];
    }

    // while there is still a remainder
    // append `=' to `enc'
    while ((i++ < 3)) {
      enc = (char *) b64_realloc(enc, size + 1);
      enc[size++] = '=';
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  enc = (char *) b64_realloc(enc, size + 1);
  enc[size] = '\0';

  return enc;
}

unsigned char *
b64_decode (const char *src, size_t len) {
  return b64_decode_ex(src, len, NULL);
}

unsigned char *
b64_decode_ex (const char *src, size_t len, size_t *decsize) {
  int i = 0;
  int j = 0;
  int l = 0;
  int valid = 0;
  size_t size = 0;
  unsigned char *dec = NULL;
  unsigned char buf[3];
  unsigned char tmp[4];

  // alloc
  dec = (unsigned char *) b64_malloc(1);
  if (NULL == dec) { return NULL; }

  // parse until end of source
  len -= len%4;
  while (len--) {
    /* ignore invalid characters */
    if (unb64_table[src[j]] > 64) return NULL;

    // read up to 4 bytes at a time into `tmp'
    tmp[i++] = src[j++];

    // if 4 bytes read then decode into `buf'
    if (4 == i) {
      valid = (tmp[2] == '=') ? 1 : (tmp[3] == '=') ? 2 : 3;

      // translate values in `tmp' from table
      for (i = 0; i < 4; ++i) {
        // find translation char in `unb64_table'
        tmp[i] = unb64_table[tmp[i]];
      }

      // decode
      buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
      buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
      buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

      // write decoded buffer to `dec'
      dec = (unsigned char *) b64_realloc(dec, size + valid);
      if (dec != NULL){
        for (i = 0; i < valid; ++i) {
          dec[size++] = buf[i];
        }
      } else {
        return NULL;
      }

      // reset
      i = 0;
    }
  }

  // remainder
  if (i > 0) {
    // fill `tmp' with `\0' at most 4 times
    for (j = i; j < 4; ++j) {
      tmp[j] = '\0';
    }

    // translate remainder
    for (j = 0; j < 4; ++j) {
        // find translation char in `unb64_table'
        tmp[j] = unb64_table[tmp[j]];
    }

    // decode remainder
    buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
    buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
    buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

    // write remainer decoded buffer to `dec'
    dec = (unsigned char *) b64_realloc(dec, size + (i - 1));
    if (dec != NULL){
      for (j = 0; (j < i - 1); ++j) {
        dec[size++] = buf[j];
      }
    } else {
      return NULL;
    }
  }

  // Make sure we have enough space to add '\0' character at end.
  dec = (unsigned char *) b64_realloc(dec, size + 1);
  if (dec != NULL){
    dec[size] = '\0';
  } else {
    return NULL;
  }

  // Return back the size of decoded string if demanded.
  if (decsize != NULL) {
    *decsize = size;
  }

  return dec;
}