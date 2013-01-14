#ifndef _GEN_KEY_H
#define _GEN_KEY_H

int gen_key(unsigned char *key, int key_length);
int gen_key_RSA(const char * const pub_key_file, const char * const priv_key_file);

#endif
