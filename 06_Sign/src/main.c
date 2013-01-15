#include "sign.h"
#include "gen_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEY_LENGTH
#define KEY_LENGTH (16)
#endif

int main(int argc, char ** argv)
{
		unsigned char * pub_key_file ="pubkey";
		unsigned char * priv_key_file ="privkey";
		int ret = 0;
		unsigned char * message = "il est important de bien savoir utiliser la librairie openssl, sinon vous n'avez rien a faire ici";
		unsigned char * ciphered_text = NULL;
		int ciphered_text_len = 0;
//		unsigned char * symetric_key = NULL;
//		unsigned char * original_text = NULL;
//		int original_text_len = 0;

		// generation des bi-cles RSA		
		ret = gen_key_RSA(pub_key_file, priv_key_file);
		
		// operation de signature
		if ( (ret = sign(ciphered_text, message, strlen(message), priv_key_file) ) !=0)
		{
				printf("An error occured while signing buffer. Program will now exit.");
				goto cleanup;
		}

		// recuperation de ce quon a precedemment chiffre: on dechiffre
		// if( (ret = decipher_buffer(&original_text, &original_text_len, ciphered_text, ciphered_text_len, 			//	priv_key_file)) != 0){
		//		printf("An error occured while deciphering buffer. Program will now exit.");
		//		goto cleanup;
		//}
		//printf("ciphered text: %s\n", ciphered_text);
cleanup:
		if(ciphered_text){
			memset(ciphered_text,0, ciphered_text_len);
			free(ciphered_text);
		}

		/* if(original_text){
			memset(original_text,0, original_text_len);
		} */
		return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

