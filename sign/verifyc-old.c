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
		return -1;
	}
	
	const char *filename = argv[1];
	const char *sigfile = argv[2];
	const char *pubkeyfile = argv[3];

	unsigned bytes = 0;

	// Calculate SHA256 digest for datafile
	FILE* datafile = fopen(filename , "rb");

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

	// Read signature from file
	FILE* sign = fopen (sigfile , "r");

	bytes = fread(buffer, 1, BUFFER_SIZE, sign);
	fclose(sign);
 
	// Verify that calculated digest and signature match
	FILE* pubkey = fopen(pubkeyfile, "r"); 

	// Read public key from file
	RSA* rsa_pubkey = PEM_read_RSA_PUBKEY(pubkey, NULL, NULL, NULL);

	// Decrypt signature (in buffer) and verify it matches
	// with the digest calculated from data file.
	int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, buffer, bytes, rsa_pubkey);
	RSA_free(rsa_pubkey);
	fclose(pubkey);

	if (result == 1) {
		printf("Signature is valid\n");
		return 0;
	} else {
		printf("Signature is invalid\n");
		return 1;
	}
}

