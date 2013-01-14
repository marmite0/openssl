#include "deriv.h"
#include "protect_file.h"

#include "polarssl/rsa.h"
#include "polarssl/config.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>


const unsigned char padding[16] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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

int cipher_buffer(unsigned char **output, int *output_len
	unsigned char *input, int input_len,
	char *pub_key_file,
	unsigned char *key);

{
	int ret;
	int i;
	unsigned char *input_padd;
	unsigned char *cipher;
	
	unsigned char key[256];
	FILE *fkey
	rsa_context rsa_ctx;
	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	char *pers = "rsa_encrypt";

	fflush( stdout );

    	entropy_init( &entropy );
    	if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy, (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    	{
        	printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        	goto cleanup;
    	}


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

    	rsa.len = ( mpi_msb( &rsa_ctx.N ) + 7 ) >> 3;

    	fclose( fkey );
	
	/* *** chiffrement RSA de KM *** */
	if( ( ret = rsa_pkcs1_encrypt( &rsa_ctx, 0, NULL, RSA_PUBLIC, 32, key, ciphered, key ) ) != 0 ) {
	        printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        	goto cleanup;
	}

	
	*output = cipher;
	*output_len = input_len + pad_len + 32;

	ret = 0;
cleanup:
	/*if(input_padd != NULL)
		free(input_padd);
	if(cipher != NULL)
		free(cipher);*/
	memset(&aes_ctx, 0x00, sizeof(aes_context));
	memset(k_m, 0x00, 32);
	memset(k_c, 0x00, 32);
	memset(k_i, 0x00, 32);
	memset(tmp_1, 0x00, 36);

	return ret;
}

