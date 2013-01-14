#ifndef _HYBRID_PROTECT_FILE_H
#define _HYBRID_PROTECT_FILE_H

/**
 * @param [out] output cipher text buffer
 * @param [out] output_len cipher text buffer length in bytes
 * @param [in] input ciphered text buffer
 * @param [in] input_len ciphered text buffer length in bytes
 * @param [in] pub_key_file public parameters file
 * @param [in] key symetric key (16 bytes)
 * @return 0 if OK, 1 else
*/

int cipher_buffer(unsigned char **output, int *output_len,
	unsigned char *input, int input_len,
	unsigned char *pub_key_file,
	unsigned char *key);

#endif
