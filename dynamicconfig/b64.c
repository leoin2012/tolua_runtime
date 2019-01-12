
/**
 * `b64.c' - b64
 * fast base64 that support custom alphabet 
 * copyright (c) 2019 shuchangliu
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
  b64_encode (const unsigned char *input, size_t input_size) {
    int i = 0;
    int j = 0;
    char *output = NULL;
    size_t size = 0;
    unsigned char encoded[4];
    unsigned char atom[3];

  // alloc
    output = (char *) b64_malloc(1);
    if (NULL == output) { return NULL; }

  // parse until end of source
    while (input_size--) {
    // read up to 3 bytes at a time into `atom'
      atom[i++] = *(input++);

    // if 3 bytes read then encode into `encoded'
      if (3 == i) {
        encoded[0] = (atom[0] & 0xfc) >> 2;
        encoded[1] = ((atom[0] & 0x03) << 4) + ((atom[1] & 0xf0) >> 4);
        encoded[2] = ((atom[1] & 0x0f) << 2) + ((atom[2] & 0xc0) >> 6);
        encoded[3] = atom[2] & 0x3f;

      // allocate 4 new byts for `output` and
      // then translate each encoded buffer
      // part by index from the base 64 index table
      // into `output' unsigned char array
        output = (char *) b64_realloc(output, size + 4);
        for (i = 0; i < 4; ++i) {
          output[size++] = b64_table[encoded[i]];
        }

      // reset index
        i = 0;
      }
    }

  // remainder
    if (i > 0) {
    // fill `atom' with `\0' at most 3 times
      for (j = i; j < 3; ++j) {
        atom[j] = '\0';
      }

    // perform same codec as above
      encoded[0] = (atom[0] & 0xfc) >> 2;
      encoded[1] = ((atom[0] & 0x03) << 4) + ((atom[1] & 0xf0) >> 4);
      encoded[2] = ((atom[1] & 0x0f) << 2) + ((atom[2] & 0xc0) >> 6);
      encoded[3] = atom[2] & 0x3f;

    // perform same write to `output` with new allocation
      for (j = 0; (j < i + 1); ++j) {
        output = (char *) b64_realloc(output, size + 1);
        output[size++] = b64_table[encoded[j]];
      }

    // while there is still a remainder
    // append `=' to `output'
      while ((i++ < 3)) {
        output = (char *) b64_realloc(output, size + 1);
        output[size++] = '=';
      }
    }

  // Make sure we have enough space to add '\0' character at end.
    output = (char *) b64_realloc(output, size + 1);
    output[size] = '\0';

    return output;
  }

  unsigned char *
  b64_decode (const char *input, size_t input_size) {
    return b64_decode_ex(input, input_size, NULL);
  }

  unsigned char *
  b64_decode_ex (const char *input, size_t input_size, size_t *output_size) {
    int i = 0;
    int j = 0;
    int l = 0;
    int valid = 0;
    size_t size = 0;
    unsigned char *output = NULL;
    unsigned char decode[3];
    unsigned char atom[4];

  // alloc
    output = (unsigned char *) b64_malloc((unsigned int)(input_size / 4 * 3));
    if (NULL == output) { return NULL; }

  // parse until end of source
    while (input_size--) {
    /* ignore invalid characters */
      if (unb64_table[input[j]] > 64) return NULL;

    // read up to 4 bytes at a time into `atom'
      atom[i++] = input[j++];

    // if 4 bytes read then decode into `decode'
      if (4 == i) {
        valid = (atom[2] == '=') ? 1 : (atom[3] == '=') ? 2 : 3;

      // translate values in `atom' from table
        for (i = 0; i < 4; ++i) {
        // find translation char in `unb64_table'
          atom[i] = unb64_table[atom[i]];
        }

      // decode
        decode[0] = (atom[0] << 2) + ((atom[1] & 0x30) >> 4);
        decode[1] = ((atom[1] & 0xf) << 4) + ((atom[2] & 0x3c) >> 2);
        decode[2] = ((atom[2] & 0x3) << 6) + atom[3];

      // write decoded buffer to `output'
        if (output != NULL){
          for (i = 0; i < valid; ++i) {
            output[size++] = decode[i];
          }
        } else {
          return NULL;
        }

      // reset
        i = 0;
      }
    }

  // Make sure we have enough space to add '\0' character at end.
    output = (unsigned char *) b64_realloc(output, size + 1);
    if (output != NULL){
      output[size] = '\0';
    } else {
      return NULL;
    }

  // Return back the size of decoded string if demanded.
    if (output_size != NULL) {
      *output_size = size;
    }

    return output;
  }