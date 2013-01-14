#ifndef _GEN_KEY_H
#define _GEN_KEY_H

/**
 * @param [out] key (32 bytes)
 * @param [in]  passwd        user password
 * @param [in]  salt          salt
 * @param [in]  salt_len      salt length in bytes
 * @param [in]  iterations    number of iterations
 *
 * @return      0 if OK, 1 else
 */
int deriv_passwd(unsigned char *key,
		char *password,
		unsigned char *salt, int salt_len,
		unsigned int iterations);

#endif
