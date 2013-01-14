#include "hybrid_protect_file.h"
#include "hybrid_unprotect_file.h"
#include "gen_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEY_LENGTH
#define KEY_LENGTH (32)
#endif

int main(int argc, char ** argv)
{
		unsigned char * pub_key_file ="pubkey";
		unsigned char * priv_key_file ="privkey";
		int ret = 0;
		unsigned char * message = "il est important de bien savoir utiliser la librairie openssl, sinon vous n'avez rien a faire ici";
		unsigned char * ciphered_text = NULL;
		int ciphered_text_len = 0;
		int opt;
		unsigned char * symetric_key = NULL;
		char * original_text = NULL;
		int original_text_len = 0;

		ret = gen_key_RSA(pub_key_file, priv_key_file);
		
		symetric_key = (unsigned char *)malloc(KEY_LENGTH*sizeof(unsigned char));
		memset(symetric_key, 0, KEY_LENGTH);

		//generation de la clef symetrique de KEY_LENGTH octets
		gen_key(symetric_key, KEY_LENGTH);
		
		// operation de chiffrement
		if( (ret = cipher_buffer(&ciphered_text, &ciphered_text_len, message, strlen(message), pub_key_file, symetric_key)) != 0){
				printf("An error occured while ciphering buffer. Program will now exit.");
				goto cleanup;
		}

		// recuperation de ce quon a precedemment chiffre: on dechiffre
		if( (ret = decipher_buffer((unsigned char **) &original_text, &original_text_len, ciphered_text, ciphered_text_len, 				priv_key_file)) != 0){
				printf("An error occured while deciphering buffer. Program will now exit.");
				goto cleanup;
		}
		printf("Original text:\n%s", original_text);
cleanup:
		if(symetric_key){
			memset(symetric_key, 0, KEY_LENGTH);
			free(symetric_key);
		}

		if(ciphered_text){
			memset(ciphered_text,0, ciphered_text_len);
			free(ciphered_text);
		}

		if(original_text){
			memset(original_text,0, original_text_len);
		}
		return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

