#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
 
// Buffer for file read operations. The buffer must be able to accomodate
// the RSA signature in whole (e.g. 4096-bit RSA key produces 512 byte signature)

#define BUFFER_SIZE 512
static unsigned char buffer[BUFFER_SIZE];
 
int main(int argc, char *argv[])
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s datafile signature_file public_key\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	
	const char *filename = argv[1];
	const char *sigfile = argv[2];
	const char *pubkeyfile = argv[3];

	unsigned bytes = 0;

	// Calculate SHA256 digest for datafile
	printf("hashing datafile...\n");
	FILE* datafile;
      	if ((datafile = fopen(filename , "rb")) == NULL) {
		fprintf(stderr, "unable to open datafile %s\n", filename);
		exit(EXIT_FAILURE);
	}

	// Buffer to hold the calculated digest
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	// Read data in chunks and feed it to OpenSSL SHA256
	while((bytes = fread(buffer, 1, BUFFER_SIZE, datafile))) {
		SHA256_Update(&ctx, buffer, bytes);
	}

	SHA256_Final(digest, &ctx);
	fclose(datafile);

	// read signature file into new buffer
	printf("reading signature file...\n");
	FILE *sigb64;
	if ((sigb64 = fopen(sigfile, "rb")) == NULL) {
		fprintf(stderr, "unable to open signature file %s\n", sigfile);
		exit(EXIT_FAILURE);
	}
	fseek(sigb64, 0L, SEEK_END);
	unsigned sigb64_filelen = ftell(sigb64);
	char *sigb64_buffer = malloc(sigb64_filelen);
	if (sigb64_buffer == NULL) {
		fprintf(stderr, "error allocating sigb64_buffer\n");
		exit(EXIT_FAILURE);
	}
	rewind(sigb64);
	fread(sigb64_buffer, 1, sigb64_filelen, sigb64);

	// decode base64 representation of signature and place in buffer
	// decoded signature is assumed to be 512 bytes in length. If unsure of
	// the length, allocate a buffer that is the size of the encoded text
	// (it will decode to be smaller anyway)
	BIO *b64, *bmem;
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(sigb64_buffer, sigb64_filelen);
	bmem = BIO_push(b64, bmem);
	BIO_read(bmem, buffer, sigb64_filelen);
	BIO_free_all(bmem);
	bytes = BUFFER_SIZE; // 512 bytes

	// Verify that calculated digest and signature match
	printf("reading public key...\n");
	FILE* pubkey;
	if ((pubkey = fopen(pubkeyfile, "r")) == NULL) {
		fprintf(stderr, "unable to open public key file %s\n", pubkeyfile);
		exit(EXIT_FAILURE);
	}	

	// Read public key from file
	RSA* rsa_pubkey = PEM_read_RSA_PUBKEY(pubkey, NULL, NULL, NULL);

	// Decrypt signature (in buffer) and verify it matches
	// with the digest calculated from data file.
	printf("decrypting signature...\n");
	int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, buffer, bytes, rsa_pubkey);
	RSA_free(rsa_pubkey);
	fclose(pubkey);

	if (result == 1) {
		printf("signature OK\n");
		exit(EXIT_SUCCESS);
	} else {
		printf("signature INVALID\n");
		exit(EXIT_FAILURE);
	}
}

