#include "gen_key.h"
#include "polarssl/havege.h"
#include "polarssl/rsa.h"
#include "polarssl/aes.h"

#include <string.h>
#include <stdio.h>

#define RSA_KEY_LENGTH_BITS (1024)
#define EXPONENT (65537) // 2^16 +1

int gen_key(unsigned char *key, int key_length)
{
	int ret;
	havege_state ctx;

	ret = 1; //error

	/* *** check argument *** */
	if((key == NULL) || (key_length <= 0))
		goto cleanup;

	havege_init(&ctx);

	ret = havege_random(&ctx, key, key_length);
cleanup:
	memset(&ctx, 0x00, sizeof(havege_state));
	return ret;
}

int gen_key_RSA(const char * const pub_key_file, const char * const priv_key_file)
{
		int error = 0;
		int ret;
		FILE *pub_key = NULL, *priv_key = NULL;
		rsa_context rsa_ctxt;
		havege_state prng_ctxt;
		int rsa_ctxt_ok = 0;

		//generation de la biclef RSA
		havege_init(&prng_ctxt);
		rsa_init(&rsa_ctxt, RSA_PKCS_V15,0);
		rsa_gen_key(&rsa_ctxt, havege_random, &prng_ctxt, RSA_KEY_LENGTH_BITS, EXPONENT);

		// export des cles publiques dans un fichier
		// ouverture du fichier
		if( ( pub_key = fopen( pub_key_file, "wb+" ) ) == NULL ){
				printf("Can not open %s to write public keys", pub_key_file);
				error = 1;
				goto cleanup;
		}
		// ecriture effective dans le fichier
		if( ( ret = mpi_write_file( "N = ", &rsa_ctxt.N, 16, pub_key ) ) != 0 ||
						( ret = mpi_write_file( "E = ", &rsa_ctxt.E, 16, pub_key ) ) != 0 ){
				printf("Can not write public keys" );
				error = 1;
				goto cleanup;
		}

		// export des cles privees dans un fichier
		// ouverture du fichier
		if( ( priv_key = fopen( priv_key_file, "wb+" ) ) == NULL ){
				printf("Can not open %s to write private keys", priv_key_file );
				error = 1;
				goto cleanup;
		}

		// ecriture effective dans le fichier
		if( ( ret = mpi_write_file( "N = " , &rsa_ctxt.N , 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "E = " , &rsa_ctxt.E , 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "D = " , &rsa_ctxt.D , 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "P = " , &rsa_ctxt.P , 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "Q = " , &rsa_ctxt.Q , 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "DP = ", &rsa_ctxt.DP, 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "DQ = ", &rsa_ctxt.DQ, 16, priv_key) ) != 0 ||
						( ret = mpi_write_file( "QP = ", &rsa_ctxt.QP, 16, priv_key) ) != 0 )	{
				printf( " failed\n  ! mpi_write_file returned %d\n\n", ret );
				goto cleanup;
		}
		rsa_ctxt_ok = 1;

cleanup:
		// liberation et/ou nettoyage de la mémoire
		if(rsa_ctxt_ok){
				rsa_free(&rsa_ctxt);
		}
		memset(&prng_ctxt, 0, sizeof(havege_state));
		if(pub_key){
				fclose(pub_key);
		}
		if(priv_key){
				fclose(priv_key);
		}
		return error;
}
