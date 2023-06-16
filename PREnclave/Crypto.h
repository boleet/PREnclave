#pragma once
#include <openssl/rsa.h>

class Crypto
{
public:
	Crypto(void);
	~Crypto(void);


	int simple_addition(char* data, size_t len);

	int rsa_load_private_key_proxy(); // TODO deprecate
	int rsa_set_private_key_proxy(unsigned char* privatekey, size_t privatekey_len);
	int rsa_get_public_key_proxy(unsigned char* publickey, size_t publickey_len);
	int rsa_session_client(unsigned char* publickey_client, size_t publickey_client_len);
	int rsa_encrypt_client(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len);
	int rsa_decrypt_proxy(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len);

	int aes_set_key_db(unsigned char* key_db, size_t key_db_len);
	int aes_session_client(unsigned char* key, unsigned char* iv);
	int aes_session_client_backward();
	int aes_get_session_client_encrypted(unsigned char* key, size_t key_len, unsigned char* iv, size_t iv_len);
	int aes_encrypt_client(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len);
	int aes_decrypt_client(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len);
	int aes_encrypt_db(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len);
	int aes_decrypt_db(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len);


private:
	EVP_CIPHER_CTX* aes_ctx_enc_client;
	EVP_CIPHER_CTX* aes_ctx_dec_client;
	unsigned char aes_key_client[32];
	unsigned char aes_iv_client[16];
	unsigned char aes_key_client_backward[32];
	unsigned char aes_iv_client_backward[16];

	EVP_CIPHER_CTX* aes_ctx_enc_db;
	EVP_CIPHER_CTX* aes_ctx_dec_db;
	unsigned char root_key_db[32];
	unsigned char aes_key_db[32];
	unsigned char mac_key_db[32];

	EVP_PKEY_CTX* rsa_ctx_enc_client;
	EVP_PKEY* rsa_keys_client;

	EVP_PKEY_CTX* rsa_ctx_dec_proxy;
	EVP_PKEY* rsa_keys_proxy;

	bool rsa_proxy_initialized;
	bool rsa_client_initialized;
	bool aes_client_initialized;
	bool aes_client_initialized_backward;
	bool aes_db_initialized;
};


