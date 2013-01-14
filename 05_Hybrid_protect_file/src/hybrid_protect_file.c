#include "polarssl/rsa.h"
#include "polarssl/aes.h"
#include "polarssl/config.h"
#include "polarssl/havege.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hybrid_protect_file.h>

#ifndef KEY_LENGTH
#define KEY_LENGTH (32)
#endif

int print_hex2(
		unsigned char *buffer, 
		int buffer_len,
		char *id)
{
	int i;

	printf(">>> %s\n", id);
	printf(">>> %d\n", buffer_len);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
	
	return 0;
}

int cipher_buffer(unsigned char **output, int *output_len,
	unsigned char *input, int input_len,
	unsigned char *pub_key_file,
	unsigned char *key)

{
	int ret;
	int i;
	
	FILE *fkey;
	rsa_context rsa_ctx;
	havege_state prng_ctx;
	aes_context aes_ctx;
	int pad_len;
	unsigned char *input_padd;
	unsigned char *cipher;
	unsigned char k_c[128];
	unsigned char padding[16] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	unsigned char iv[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	/* ********************* PARTIE SYMETRIQUE ************************ */

	/* *** Initialisation *** */
	
	input_padd = NULL;
	cipher = NULL;
	pad_len=0;

	/* *** Padding ?! bloc de 128 bits = 16 octets *** */
	/* *** on cherche le reste du multiple de 16, et la difference avec 16 sera la longueur de padding à completer *** */

	pad_len = 16 - (input_len % 16);
	input_padd = (unsigned char *)malloc((input_len + pad_len)*sizeof(char));
	if(input_padd == NULL)
		goto cleanup;

	/* *** allocation du message chiffre *** */

	cipher = (unsigned char *)malloc((input_len + pad_len)*sizeof(char));
	if(cipher == NULL)
		goto cleanup;

	/* on copie dans input_padd le message clair */
	memcpy(input_padd, input, input_len);
	/* on copie à la fin de input_padd, le padding */
	memcpy(input_padd+input_len, padding, pad_len);


	/* *** chiffrement avec la cle symetrique *** */
	ret = aes_setkey_enc(&aes_ctx, key, 256);
	if(ret != 0)
		goto cleanup;

	/* encrypt message clair + padding de longueur input_len + pad_len, sortie cipher */
	ret = aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, (size_t) (input_len + pad_len), (unsigned char *)iv, input_padd, cipher);
	if(ret != 0)
		goto cleanup;

	/* ********************** PARTIE ASSYMETRIQUE *********************** */


	/* *** Read the public asymetric key in the file*** */
	if( ( fkey = fopen( pub_key_file, "rb" ) ) == NULL ) {		
        	ret = 1;
       		printf( " failed\n  ! Could not open %s\n" \
                "  ! Please run rsa_genkey first\n\n",pub_key_file );
        	goto cleanup;
	}

	/* *** initialisation du contexte RSA avec la cle publique *** */
	rsa_init( &rsa_ctx, RSA_PKCS_V15, 0 );
	
	if( ( ret = mpi_read_file( &rsa_ctx.N, 16, fkey ) ) != 0 || ( ret = mpi_read_file( &rsa_ctx.E, 16, fkey ) ) != 0 ) {
	        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        	goto cleanup;
	}

    	rsa_ctx.len = ( mpi_msb( &rsa_ctx.N ) + 7 ) >> 3;

    	fclose( fkey );
	
	/* *** SYM_K(key) : chiffrement RSA de la clé de chiffrement key (16) => rsa-1024 bits = 128 octets en sortie *** */
	havege_init(&prng_ctx);
	memset(k_c, 0, 128);
	if( ( ret = rsa_pkcs1_encrypt( &rsa_ctx, havege_random, &prng_ctx, RSA_PUBLIC, KEY_LENGTH, key, k_c ) ) != 0 ) {
	        printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        	goto cleanup;
	}

	/* *** cipher = ASYM_Kpub (K) || SYM_K(plain) *** */
	*output = (unsigned char *) malloc((128+ input_len + pad_len) * sizeof(unsigned char));
	/* *** ASYM_Kpub (K) *** */
	memcpy(*output, k_c, 128);
	/* *** ASYM_Kpub (K) || SYM_K(plain) *** */
	memcpy(*output+128, cipher, input_len + pad_len);

	*output_len = 128 + input_len + pad_len;

cleanup:
	if(input_padd != NULL) {
		memset(input_padd, 0, pad_len);
		free(input_padd);
	}
	if(cipher != NULL) {
		memset(cipher, 0, input_len + pad_len);
		free(cipher);
	}
	memset(&aes_ctx, 0x00, sizeof(aes_ctx));
	memset(&prng_ctx,0x00, sizeof(havege_state));
	memset(&rsa_ctx, 0x00, sizeof(rsa_ctx));
	memset(k_c, 0, 128);

	return ret;
}

