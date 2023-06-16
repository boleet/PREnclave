#include "PREnclave_t.h"

#include "sgx_trts.h"
#include <string.h>
#include "Crypto.h"
#include <openssl/evp.h>
#include <string>
#include <vector>

int secretvalue = 1;
Crypto myCrypto;

// Dummy function that returns an integer
int e_hello()
{
	return secretvalue;
}

// Initialize enclave; not doing much at the moment
int e_initialize() {
	secretvalue = 42; // dummy operation
	return 1;
}

// Use one session per client request (which can include multiple SQL queries and parameters, and multiple data in return)
// which entails an AES session (key, IV) and RSA session (to encrypt key,IV towards client public key)
int e_session(unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len, unsigned char* publickey_client, size_t publickey_client_len) {
	secretvalue += 1; // dummy operation

	if (publickey_client_len == 0) {
		return 101;
	}

	// set RSA session
	int x = myCrypto.rsa_session_client(publickey_client, publickey_client_len);
	if (x != 1) {
		return 200 + x;
	}

	x = myCrypto.aes_session_client_backward();
	if (x != 1) {
		return 102;
	}

	if (key_enc_len != 256 || iv_enc_len != 256) { // If we only want to set the public key, return here (note: hardcoded encrypted key and IV lengths)
		return 103;
	}

	std::vector<unsigned char> key(256, 0);
	size_t key_len = key.size();
	x = myCrypto.rsa_decrypt_proxy(key_enc, key_enc_len, key.data(), &key_len);
	if (x != 1) {
		return 300 + x;
	}

	if (key_len != 32) { // Check key length for AES256
		return 104;
	}
	key.resize(key_len);

	//unsigned char iv[256] = {};
	std::vector<unsigned char> iv(256, 0);
	size_t iv_len = iv.size();
	x = myCrypto.rsa_decrypt_proxy(iv_enc, iv_enc_len, iv.data(), &iv_len);
	if (x != 1) {
		return 400 + x;
	}

	if (iv_len != 16) { // Check iv length for AES256
		return 105;
	}
	iv.resize(iv_len);

	// set AES session
	x = myCrypto.aes_session_client(key.data(), iv.data());
	if (x != 1) {
		return 500 + x;
	}

	return 1;
}

// Encrypted the aes session key and IV towards the client public key, such that the client can retrieve them and knows how to decrypt the aes encrypted data
int e_get_session_client(unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len) {
	int x = myCrypto.aes_get_session_client_encrypted(key_enc, key_enc_len, iv_enc, iv_enc_len);
	if (x != 1) {
		return 100 + x;
	}

	return 1;
}

// Decrypt data from client hybrid encryption, encrypt towards database
int e_PREForward(unsigned char* data, size_t data_ln, unsigned char* result, size_t result_len)
{
	// Decrypt client data
	size_t plain_size = data_ln; // plain size cannot be larger than encrypted size, thus this should be sufficient
	std::vector<unsigned char> plain(plain_size, 0);
	int x = myCrypto.aes_decrypt_client(data, data_ln, &plain[0], &plain_size);
	if (x != 1) {
		return 100 + x;
	}

	// Trim plaintext
	while (!plain.empty() && plain[plain.size() - 1] == 0) {
		plain.pop_back();
	}

	// Re-encrypyt towards database
	x = myCrypto.aes_encrypt_db(&plain[0], plain_size, result, &result_len);
	if (x != 1) {
		return 200 + x;
	}

	return 1;
}

// Decrypt data from database, encrypt towards client with hybrid encryption
int e_PREBackward(unsigned char* data, size_t data_len, unsigned char* result, size_t result_len)
{
	// Decrypt from database
	size_t plain_size = data_len - 1 - 32 - 16; // Size is always smaller than encrypted data size (minus version byte, MAC, IV)
	std::vector<unsigned char> plain(plain_size, 0);


	int x = myCrypto.aes_decrypt_db(data, data_len, &plain[0], &plain_size);
	if (x != 1) {
		return 100 + x;
	}
	plain.resize(plain_size);

	// Encrypt towards client
	x = myCrypto.aes_encrypt_client(&plain[0], plain_size, result, &result_len);
	if (x != 1) {
		return 200 + x;
	}

	return 1;
}



// Allows the database CEK to be set from the untrusted environment for simplicity in this prototype
int e_set_key_db_insecure(unsigned char* key_db, size_t key_db_len) {
	int x = myCrypto.aes_set_key_db(key_db, key_db_len);
	if (x != 1) {
		return 100 + x;
	}
	return 1;
}

// Allows the proxy RSA private key to be set from the untrusted environment for simplicity in this prototype
int e_set_private_key_proxy_insecure(unsigned char* key_proxy, size_t key_proxy_len) {
	int x = myCrypto.rsa_set_private_key_proxy(key_proxy, key_proxy_len);
	if (x != 1) {
		return 100 + x;
	}
	return 1;
}

// Returns the RSA public key of this proxy
int e_get_public_key_proxy(unsigned char* publickey, size_t publickey_len) {
	int x = myCrypto.rsa_get_public_key_proxy(publickey, publickey_len);
	if (x != 1) {
		return 100 + x;
	}
	return 1;
}


