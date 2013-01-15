#include "polarssl/rsa.h"
#include "polarssl/sha2.h"
#include "polarssl/havege.h"
#include "gen_key.h"
#include "sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEY_LENGTH
#define KEY_LENGTH (16)
#endif

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

int verif(unsigned char *sign,unsigned char *input, int input_len,char *pub_key_file)

{
	unsigned char * cipher = NULL;
	unsigned char * k_c = NULL;
	unsigned char sign[128];
	int ret;
	
	FILE *fkey;
	rsa_context rsa_ctx;
	havege_state prng_ctx;

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

	
	cipher = (unsigned char *)malloc((32)*sizeof(char));

	/* ********************** HASH controle integrite *********************** */

	k_c = (unsigned char *)malloc(2*KEY_LENGTH*sizeof(unsigned char));
	memset(k_c, 0, 2*KEY_LENGTH);

	//generation de la clef symetrique de KEY_LENGTH bits
	gen_key(k_c, KEY_LENGTH);
	sha2_hmac(k_c, KEY_LENGTH, input, input_len, cipher, 0);

	print_hex(k_c, KEY_LENGTH, "cle secrete utilisée pour le hash : ");

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
	/* *** cipher = ASYM_Kpriv (Hash) *** */
	havege_init(&prng_ctx);
	memset(sign, 0, 128);
	if( ( ret = rsa_pkcs1_encrypt( &rsa_ctx, havege_random, &prng_ctx, RSA_PRIVATE, KEY_LENGTH, cipher, sign ) ) != 0 ) {
	        printf( " failed\n  ! rsa_pkcs1_encrypt returned %d\n\n", ret );
        	goto cleanup;
	}

	print_hex(sign, sizeof(sign), "Hash chiffrée avec RSA : ");

	/* *** ASYM_Kpub (K) *** */
	output = (unsigned char *) malloc( 128 * sizeof(unsigned char));
	memcpy(output, sign, 128);

cleanup:
	if(cipher != NULL) {
		memset(cipher, 0, 32);
		free(cipher);
	}
	if(k_c != NULL) {
		memset(k_c, 0, 2*KEY_LENGTH);
		free(k_c);
	}
	memset(&prng_ctx,0x00, sizeof(havege_state));
	memset(&rsa_ctx, 0x00, sizeof(rsa_ctx));
	memset(sign, 0, 128);

	return ret;
}

