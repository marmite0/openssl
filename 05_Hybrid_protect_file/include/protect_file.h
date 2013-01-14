#ifndef _PROTECT_FILE_H
#define _PROTECT_FILE_H

/**
 * @param [out] output        ciphered buffer
 * @param [out] output_len    ciphered buffer length in bytes
 * @param [in]  input         plain text buffer
 * @param [in]  input_len     plain text buffer length in bytes
 * @param [in]  passwd        user password
 * @param [in]  salt          salt
 * @param [in]  salt_len      salt length in bytes
 * @param [in]  iterations    number of iterations
 * @return      0 if OK, 1 else
 */

int protect_buffer(unsigned char **output, int *output_len,
		unsigned char *input, int input_len,
		char *password,
		unsigned char *salt, int salt_len,
		unsigned int iterations);

#endif
