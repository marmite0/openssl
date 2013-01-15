#ifndef _SIGN_FILE_H
#define _SIGN_FILE_H

/**
* @param [out] output cipher text buffer
* @param [out] output_len cipher text buffer length in bytes
* @param [in] input ciphered text buffer
* @param [in] input_len ciphered text buffer length in bytes
* @param [in] pri_key_file private parameters file
* @return 0 if OK, 1 else
*/

int sign(unsigned char *output,unsigned char *input, int input_len, char *pri_key_file);

#endif
