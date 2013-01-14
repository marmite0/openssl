#include "polarssl/rsa.h"
#include "polarssl/aes.h"
#include "polarssl/config.h"
#include "polarssl/havege.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEY_LENGTH
#define KEY_LENGTH (32)
#endif

int search(unsigned char* input_padd, int size){
	int i;
	
	for (i=size-1; i>=0; i--) {
		if (input_padd[i]==0x80) {
			return i;
		}
	}
	
	return -1;
}

int print_hex(
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

int decipher_buffer(unsigned char **output, int *output_len,
unsigned char *input, int input_len,
char *pri_key_file)
{
	int ret;
	size_t olen;
	FILE *fkey;
	rsa_context rsa_ctx;
	aes_context aes_ctx;
	unsigned char *plain;
	unsigned char *plain_padd;
	int padding = 0;
	unsigned char k_c[128];

	unsigned char iv[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	/* ********************** PARTIE ASSYMETRIQUE *********************** */


	/* *** Read the private asymetric key in the file*** */
	if( ( fkey = fopen( pri_key_file, "rb" ) ) == NULL ) {		
        	ret = 1;
       		printf( " failed\n  ! Could not open %s\n" \
                "  ! Please run rsa_genkey first\n\n",pri_key_file );
        	goto cleanup;
	}

	rsa_init( &rsa_ctx, RSA_PKCS_V15, 0 );

	    if( ( ret = mpi_read_file( &rsa_ctx.N , 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.E , 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.D , 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.P , 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.Q , 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.DP, 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.DQ, 16, fkey ) ) != 0 ||
	        ( ret = mpi_read_file( &rsa_ctx.QP, 16, fkey ) ) != 0 )
	    {
	        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
	        goto cleanup;
	    }

	    rsa_ctx.len = ( mpi_msb( &rsa_ctx.N ) + 7 ) >> 3;

	    fclose( fkey );
	
	/* *** SYM_K(key) : chiffrement RSA de la clé de chiffrement key (16) => rsa-1024 bits = 128 octets en sortie *** */
	memset(k_c, 0, 128);
	if( ( ret = rsa_pkcs1_decrypt( &rsa_ctx, RSA_PRIVATE, &olen, input, k_c, KEY_LENGTH ) ) != 0 ) {
	        printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        	goto cleanup;
	}

	/* ********************* PARTIE SYMETRIQUE ************************ */



	/* *** dechiffrement avec la cle symetrique *** */
	ret = 1;
	ret = aes_setkey_dec(&aes_ctx, k_c, 256);
	
	print_hex(k_c, sizeof(k_c), "cle secrete : ");

	if(ret != 0) {
		fprintf(stderr, "error while setting key : \n");
		goto cleanup;
	}

	/* dechiffrement message chiffre + padding, sortie plain */
	plain_padd = (unsigned char *) malloc( (input_len - 128 ) *sizeof(char) );
	
	ret=1;
	ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, (size_t) input_len-128, (unsigned char *)iv, input+128, plain_padd);
	
	if(ret != 0) {
		fprintf(stderr, "error while decrypting cbc message : \n");
		goto cleanup;
	}
	
	/* recherche la chaine 0x80,0x00 marquant le debut du padding */ 
	padding = search(plain_padd,input_len - 128);
	plain = (unsigned char *) malloc (padding * sizeof(char));
	
	/* *** message sans le padding  *** */
	memcpy(plain, plain_padd, padding);

	*output = plain;
	*output_len = padding;

cleanup:
	if(plain_padd != NULL)
		free(plain_padd);
	if(plain != NULL)
		free(plain);
	memset(&aes_ctx, 0x00, sizeof(aes_ctx));
	memset(&rsa_ctx, 0x00, sizeof(rsa_ctx));
	memset(k_c, 0, 128);

	return ret;
}

