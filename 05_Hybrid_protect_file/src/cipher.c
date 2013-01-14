#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "polarssl/havege.h" // havege : HArdware Volatile Entropy Gathering and Expansion
#include "polarssl/aes.h"
#include "polarssl/rsa.h"
#include "logger/logger.h"

#define KEY_LENGTH (16)
#define RSA_KEY_LENGTH_BITS (1024)
#define EXPONENT (65537) // 2^16 +1
const unsigned char padding[16] = { 0x80,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/**
 * @brief Generate a random key
 *
 * @param key the buffer that will hold the key
 * @param key_length the length of the wanted key
 * @return the value returned by havege_random (0 if OK)
 */
int gen_key(unsigned char * key, int key_length)
{
		havege_state ctxt;
		havege_init( &ctxt );

		int ret = havege_random( &ctxt, key, key_length );
		memset(&ctxt,0x00,sizeof(havege_state)); // pour eviter une analyse post mortem de la memoire
		return ret;
}

/**
 * @brief Display a key in hex form
 *
 * @param key the array of unsigned char to display
 * @param key_length the length of param key in bytes
 */
void display_key(unsigned char * key, int key_length)
{
		int i;
		for(i=0; i<key_length;i++){
				printf("%02x",key[i]); //02 pour un affichage correct car 0 == 0x00 == 0x0
		}
		printf("\n");

}

/**
 * @brief Generate files containing private and public keys
 *
 * @param pub_key_file the name of the file containing the public key
 * @param priv_key_file the name of the file containing the private key
 * @return 0 if OK, 1 else
 */
int generate_keys_files(const char * const pub_key_file, const char * const priv_key_file)
{
		int error = 0;
		int ret;
		FILE *pub_key = NULL, *priv_key = NULL;
		rsa_context rsa_ctxt;
		havege_state prng_ctxt;
		bool rsa_ctxt_ok = false;

		//generation de la biclef RSA
		havege_init(&prng_ctxt);
		rsa_init(&rsa_ctxt, RSA_PKCS_V15,0);
		rsa_gen_key(&rsa_ctxt, havege_random, &prng_ctxt, RSA_KEY_LENGTH_BITS, EXPONENT);

		// export des cles publiques dans un fichier
		// ouverture du fichier
		if( ( pub_key = fopen( pub_key_file, "wb+" ) ) == NULL ){
				LOG_ERROR("Can not open %s to write public keys", pub_key_file);
				error = 1;
				goto cleanup;
		}
		// ecriture effective dans le fichier
		if( ( ret = mpi_write_file( "N = ", &rsa_ctxt.N, 16, pub_key ) ) != 0 ||
						( ret = mpi_write_file( "E = ", &rsa_ctxt.E, 16, pub_key ) ) != 0 ){
				LOG_ERROR("Can not write public keys" );
				error = 1;
				goto cleanup;
		}

		// export des cles privees dans un fichier
		// ouverture du fichier
		if( ( priv_key = fopen( priv_key_file, "wb+" ) ) == NULL ){
				LOG_ERROR("Can not open %s to write private keys", priv_key_file );
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
		rsa_ctxt_ok = true;

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


/**
 *
 * @param [in] output			cipher text buffer
 * @param [in] output_len		cipher text buffer length in bytes
 * @param [in] input			ciphered text buffer
 * @param [in] input_len		ciphered text buffer length in bytes
 * @param [in] rsa_ctxt			context rsa containing public parameters
 * @param [in] key				symetric key (16 bytes)
 * @return						0 if OK, 1 else
 */
int cipher_buffer_by_context(unsigned char ** output, int *output_len, unsigned char *input, int input_len, rsa_context *rsa_ctxt, unsigned char *key)
{
		int error = 0;
		unsigned char iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		int ret = 0;
		aes_context aes_ctxt;
		unsigned char rsa_out[128] = {0};
		havege_state prng_ctxt;
		unsigned int padding_len = 0;
		unsigned char * input_and_padding = NULL;
		unsigned char * out = NULL;

		LOG_DEBUG("================================================== CIPHER_BUFFER ========================================");


		LOG_DEBUG("Arguments are:");
		LOG_DEBUG("Input = %s", input);
		if(isDebugEnabled()){
				display_key(input, input_len);
		}
		LOG_DEBUG("Key = ");
		if(isDebugEnabled()){
				display_key(key, KEY_LENGTH);
		}

		//chiffrement aes : initialisation
		ret = aes_setkey_enc(&aes_ctxt, key, 256);
		if(ret != 0){
				LOG_ERROR("Error while calling aes_setkey_enc. Ret code is %d", ret);
				error = 1;
				goto cleanup;
		}

		// calcul de la longueur du padding : aes_256 chiffre des blocs de 16 octets,
		// on rajoute donc un padding pour obtenir des blocs de la bonne taille
		padding_len = 16 - ( input_len % 16);

		// allocation d'un buffer IN = input + padding
		input_and_padding = (unsigned char *) malloc((input_len + padding_len)*sizeof(unsigned char));
		memset(input_and_padding, 0, input_len + padding_len);

		// allocation d'un buffer OUT de longueur egale a celle de IN
		out = (unsigned char *) malloc((input_len + padding_len)*sizeof(unsigned char));
		memset(out, 0 , input_len + padding_len);

		//remplissage de input_and_padding
		memcpy(input_and_padding, input, input_len);
		memcpy(input_and_padding + input_len, padding, padding_len);

		LOG_DEBUG("Input_and_padding :");
		if(isDebugEnabled()){
				display_key(input_and_padding, input_len + padding_len);
		}

		LOG_DEBUG("input_len + padding_len = %d", input_len + padding_len);

		//operation de chiffrement aes-256-cbc
		ret = aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, input_len + padding_len, iv, input_and_padding, out);
		if(ret != 0){
				LOG_ERROR("Error while calling aes_crypt_cbc. Ret code is %d", ret);
				error = 1;
				goto cleanup;
		}

		LOG_DEBUG("Result of the ciphering of input and padding:");
		if(isDebugEnabled()){
				display_key(out, input_len + padding_len);
		}

		//chiffrement de la clef avec rsa-1024
		havege_init(&prng_ctxt);
		ret = rsa_pkcs1_encrypt( rsa_ctxt, havege_random, &prng_ctxt, RSA_PUBLIC, KEY_LENGTH, key, rsa_out);
		if(ret != 0){
				LOG_ERROR("Error while calling rsa_pkcs1_encrypt with retcode = %d", ret);
				error = 1;
				goto cleanup;
		}

		// cipher = ASYM_Kpub (K) || SYM_K(plain)
		*output = (unsigned char *) malloc((128+ input_len + padding_len) * sizeof(unsigned char));
		memcpy(*output, rsa_out, 128);
		memcpy(*output+128, out, input_len + padding_len);

		*output_len = 128 + input_len + padding_len;

		LOG_DEBUG("Complete ciphered : ASYM_Kpub(K) || SYM_K(plain)");
		if(isDebugEnabled()){
				display_key(*output, 128 + input_len + padding_len);
		}

		LOG_DEBUG("================================================== END OF CIPHER_BUFFER ========================================");

cleanup:
		if(input_and_padding){
				memset(input_and_padding, 0, input_len + padding_len);
				free(input_and_padding);
		}

		if(out){
				memset(out, 0 , input_len + padding_len);
				free(out);
		}

		memset(&prng_ctxt, 0, sizeof(havege_state));

		memset(rsa_out, 0, 128);
		memset(&aes_ctxt, 0, sizeof(aes_context));
		memset(iv, 0, 16);

		return error;
}

/**
 *
 * @param [in] output			cipher text buffer
 * @param [in] output_len		cipher text buffer length in bytes
 * @param [in] input			ciphered text buffer
 * @param [in] input_len		ciphered text buffer length in bytes
 * @param [in] pub_key_file		public parameters file
 * @param [in] key				symetric key (16 bytes)
 * @return						0 if OK, 1 else
 */
int cipher_buffer(unsigned char ** output, int *output_len, unsigned char *input, int input_len, const char * const pub_key_file, unsigned char *key)
{

		rsa_context rsa_ctxt;
		int ret = 0, error=0;
		FILE *pub_key=NULL;
		bool rsa_ctxt_ok = false;

		if( ( pub_key = fopen( pub_key_file, "rb" ) ) == NULL ){
				error = 1;
				LOG_ERROR("Can not open %s to read public key.\nPlease run this application with -g option first to generate public and private key files.", pub_key_file );
				goto cleanup;
		}

		rsa_init( &rsa_ctxt, RSA_PKCS_V15, 0 );

		if( ( ret = mpi_read_file( &rsa_ctxt.N, 16, pub_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.E, 16, pub_key ) ) != 0 ){
				LOG_ERROR("Can not read data from %s", pub_key_file);
				error = 1;
				goto cleanup;
		}

		rsa_ctxt.len = ( mpi_msb( &rsa_ctxt.N ) + 7 ) >> 3;
		rsa_ctxt_ok = true;

		error = cipher_buffer_by_context(output, output_len, input, input_len, &rsa_ctxt, key);

cleanup:
		if(pub_key){
				fclose( pub_key );
		}
		if(rsa_ctxt_ok){
				rsa_free(&rsa_ctxt);
		}

		return error;
}

/**
 * @param [in] output			cipher text buffer
 * @param [in] output_len		cipher text buffer length in bytes
 * @param [in] input			ciphered text buffer
 * @param [in] input_len		ciphered text buffer length in bytes
 * @param [in] rsa_ctxt			rsa context set with private parameters
 * @return						0 if OK, 1 else
 */
int decipher_buffer_by_context(unsigned char **output, int *output_len, unsigned char *input, int input_len, rsa_context *rsa_ctxt)
{
		int error = 0;
		int ret = 0;
		unsigned char sym_key[2*KEY_LENGTH] = {0};
		size_t key_len = 0;
		aes_context aes_ctxt_dec;
		unsigned char iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		int i;

		if(isDebugEnabled()){
				LOG_DEBUG("================================================== BEGIN OF DECIPHER_BUFFER ========================================");
				LOG_DEBUG("Arguments are :");
				LOG_DEBUG("Input =");
				display_key(input, input_len);
				LOG_DEBUG("input_len = %d", input_len);
				LOG_DEBUG("input[128]...");
				display_key(input+128, input_len - 128);
		}

		// recuperation de la clef symetrique utilisee
		// on recupere les 128 premiers octets, qui sont ceux de la clef symetrique, chiffres avec rsa-1024
		ret = rsa_pkcs1_decrypt(rsa_ctxt, RSA_PRIVATE, &key_len, input, sym_key, KEY_LENGTH);
		if(ret != 0){
				LOG_ERROR("Error while calling rsa_pkcs1_decrypt. Retcode is %d", ret);
				error = 1;
		}

		if(isDebugEnabled()){
				LOG_DEBUG("Key is:");
				display_key(sym_key, KEY_LENGTH);
				LOG_DEBUG("Key length = %d",(int) key_len);
				LOG_DEBUG("Ciphered text and padding");
				display_key(input + 128, input_len - 128);
		}

		// mise en place de la clef de dechiffrement
		ret = aes_setkey_dec( &aes_ctxt_dec, sym_key, 256);
		if(ret != 0){
				LOG_ERROR("Error while calling aes_setkey_dec. Ret code is %d", ret);
				error = 1;
		}
		LOG_DEBUG("Input_len - 128 = %d", input_len - 128);

		*output = (unsigned char *) malloc((input_len - 128)*sizeof(unsigned char));
		memset(*output, 0 , input_len - 128);

		// dechiffrement a proprement parler
		ret = aes_crypt_cbc( &aes_ctxt_dec, AES_DECRYPT, input_len - 128 , iv, input + 128, *output);
		if (ret != 0){
				LOG_ERROR("Error while calling aes_crypt_cbc. Ret code is %d", ret);
				error = 1;
		}
		// *output contient maintenant la chaine chiffree et le padding.
		// il convient donc de remplacer le 0x80 de padding par 0x00
		// ce remplacement fait que la gestion du padding n'est pas générique, et ne fonctionnerait plus
		// des lors que l'on change la chaine de padding entiere
		for (i= input_len -128 - 1; i >= 0; i--){
				if((*output)[i] == 0x80) {	//TODO make this a constant
						*output_len = i;
						(*output)[i] = 0x00; // au cas ou un jour le padding ne serait plus 0x80 suivi uniquement de 0x00
						break;
				}
		}

		LOG_DEBUG("================================================== END OF DECIPHER_BUFFER ========================================");
		return error;
}

/**
 * @param [in] output			cipher text buffer
 * @param [in] output_len		cipher text buffer length in bytes
 * @param [in] input			ciphered text buffer
 * @param [in] input_len		ciphered text buffer length in bytes
 * @param [in] priv_key_file	private parameters file
 * @return						0 if OK, 1 else
 */
int decipher_buffer(unsigned char **output, int *output_len, unsigned char *input, int input_len, const char * const priv_key_file)
{
		rsa_context rsa_ctxt;
		int ret, error = 0;
		FILE * priv_key = NULL;
		bool rsa_ctxt_ok = false;

		// lecture de la clef privee depuis le fichier
		if( ( priv_key = fopen( priv_key_file, "rb" ) ) == NULL ){
				LOG_ERROR("Can not open %s to read private key.\nPlease run this application with -g option first to generate public and private key files.", priv_key_file );
				error = 1;
				goto exit;
		}

		rsa_init( &rsa_ctxt, RSA_PKCS_V15, 0 );

		if( ( ret = mpi_read_file( &rsa_ctxt.N , 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.E , 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.D , 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.P , 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.Q , 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.DP, 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.DQ, 16, priv_key ) ) != 0 ||
						( ret = mpi_read_file( &rsa_ctxt.QP, 16, priv_key ) ) != 0 ){
				LOG_ERROR("Can not read private key from %s", priv_key_file );
				error = 1;
				goto exit;
		}

		rsa_ctxt.len = ( mpi_msb( &rsa_ctxt.N ) + 7 ) >> 3;
		rsa_ctxt_ok = true;
		error = decipher_buffer_by_context(output, output_len, input, input_len, &rsa_ctxt);

exit:
		if(priv_key){
				fclose(priv_key);
		}
		if(rsa_ctxt_ok){
				rsa_free(&rsa_ctxt);
		}
		return error;
}

/**
 * @brief
 * @param program the name of the program
 */
void usage(const char * const program)
{
		printf("Usage: %s [-d(l)] [-g] [-h]\n", program);
		printf("\nOptions:\n");
		printf("-g\t\tgenerate private and public key files\n");
		printf("-d\t\tshow debug logs, containing states of variables...\n");
		printf("-l\t\tshow location of logs in the code for debug logs\n");
		printf("-h\t\tshow this help\n");
		printf("\nReturn value:\n");
		printf("%d\t\tin case of success\n", EXIT_SUCCESS);
		printf("%d\t\tin case of error\n", EXIT_FAILURE);
}

int main(int argc, char ** argv)
{
		const char * const pub_key_file ="pub_key.txt";
		const char * const priv_key_file ="priv_key.txt";
		int ret = 0;
		const char * const message = "\"There's a difference between knowing the path and walking the path.\" Morpheus\n\"Don't think you are, know you are.\" Morpheus\n\"Never send a human to do a machine's job.\" Agent Smith";
		unsigned char * ciphered_text = NULL;
		int ciphered_text_len = 0;
		int opt;
		unsigned char * symetric_key = NULL;
		char * original_text = NULL;
		int original_text_len = 0;

		// gestion des options
		while ((opt = getopt(argc, argv, "dhlg")) != -1) {
				switch (opt) {
						case 'g':
								ret = generate_keys_files(pub_key_file, priv_key_file);
								if(ret == 0){
										LOG_DEBUG("Keys files created");
										exit(EXIT_SUCCESS);
								}else{
										LOG_ERROR("Error while creating key files");
										exit(EXIT_FAILURE);
								}
								break;
						case 'd':
								enableDebug();
								break;
						case 'h':
								usage(argv[0]);
								exit(EXIT_SUCCESS);
								break; // laisse au cas ou une modification de ce code serait a faire
						case 'l':
								showLogLocation(true);
								break;
						default:
								usage(argv[0]);
								exit(EXIT_FAILURE);
				}
		}


		symetric_key = (unsigned char *)malloc(2*KEY_LENGTH*sizeof(unsigned char));
		memset(symetric_key, 0, 2*KEY_LENGTH);

		//generation de la clef symetrique de KEY_LENGTH octets
		gen_key(symetric_key, 16);
		LOG_DEBUG("Generated symetric key is:");
		if(isDebugEnabled()){
				display_key(symetric_key, KEY_LENGTH);
		}

		// operation de chiffrement
		if( (ret = cipher_buffer(&ciphered_text, &ciphered_text_len, (unsigned char*) message, strlen(message), pub_key_file , symetric_key)) != 0){
				LOG_ERROR("An error occured while ciphering buffer. Program will now exit.");
				goto cleanup;
		}

		// recuperation de ce quon a precedemment chiffre: on dechiffre
		if( (ret = decipher_buffer((unsigned char **) &original_text, &original_text_len, ciphered_text, ciphered_text_len, priv_key_file)) != 0){
				LOG_ERROR("An error occured while deciphering buffer. Program will now exit.");
				goto cleanup;
		}
		LOG_INFO("Original text:\n%s", original_text);
cleanup:
		if(symetric_key){
			memset(symetric_key, 0, 2*KEY_LENGTH);
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
