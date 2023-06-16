#include "Crypto.h"
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <sgx_trts.h>
#include <format>
#include <vector>


Crypto::Crypto() {
	// Client session AES
	EVP_CIPHER_CTX* aes_ctx_enc_client;
	EVP_CIPHER_CTX* aes_ctx_dec_client;
	unsigned char aes_key_client[32];
	unsigned char aes_iv_client[16];
	unsigned char aes_key_client_backward[32];
	unsigned char aes_iv_client_backward[16];


	// DB session AES
	EVP_CIPHER_CTX* aes_ctx_enc_db;
	EVP_CIPHER_CTX* aes_ctx_dec_db;
	unsigned char root_key_db[32];
	unsigned char aes_key_db[32];
	unsigned char mac_key_db[32];


	// Client RSA
	EVP_PKEY_CTX* rsa_ctx_enc_client;
	EVP_PKEY* rsa_keys_client;

	// Proxy RSA
	EVP_PKEY_CTX* rsa_ctx_dec_proxy;
	EVP_PKEY* rsa_keys_proxy;

	bool aes_client_initialized = false;
	bool aes_client_initialized_backward = false;
	bool aes_db_initialized = false;
	bool rsa_client_initialized = false;
	bool rsa_proxy_initialized = false;

}

Crypto::~Crypto() {
	// TODO memory leak can exists if the initialization function partially succeed, thus the initialized variables are false but memory is allocated
	if (aes_client_initialized) {
		EVP_CIPHER_CTX_free(aes_ctx_enc_client);
		EVP_CIPHER_CTX_free(aes_ctx_dec_client);
		aes_client_initialized = false;
	}
	if (aes_db_initialized) {
		EVP_CIPHER_CTX_free(aes_ctx_enc_db);
		EVP_CIPHER_CTX_free(aes_ctx_dec_db);
		aes_db_initialized = false;
	}
	if (rsa_client_initialized) {
		EVP_PKEY_CTX_free(rsa_ctx_enc_client);
		EVP_PKEY_free(rsa_keys_client);
		rsa_client_initialized = false;
	}
	if (rsa_proxy_initialized) {
		EVP_PKEY_CTX_free(rsa_ctx_dec_proxy);
		EVP_PKEY_free(rsa_keys_proxy);
		rsa_proxy_initialized = false;
	}
}




// Dummy function to increment each byte in data by 5
int Crypto::simple_addition(char* data, size_t len)
{
	for (int i = 0; i < len; i++) {
		data[i] = data[i] + 5;
	}
	return 1;
}

/*********** RSA ************/

// Initialize RSA private key for the proxy (this enclave) with keygen
// Deprecated!
int Crypto::rsa_load_private_key_proxy() {
	return 0;


	// For now just generate a new random key
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) {
		return 10;
	}
	if (EVP_PKEY_keygen_init(ctx) != 1) {
		return 11;
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) != 1) {
		return 12;
	}
	if (EVP_PKEY_keygen(ctx, &rsa_keys_proxy) != 1) {
		return 13;
	}

	if (rsa_proxy_initialized) {
		EVP_PKEY_CTX_free(rsa_ctx_dec_proxy); // Free possible previous session
		rsa_proxy_initialized = false;
	}

	if (!(rsa_ctx_dec_proxy = EVP_PKEY_CTX_new(rsa_keys_proxy, NULL))) {
		return 14;
	}

	EVP_PKEY_CTX_free(ctx);

	// Set decryption context

	if (EVP_PKEY_decrypt_init(rsa_ctx_dec_proxy) != 1) {
		return 10;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(rsa_ctx_dec_proxy, RSA_PKCS1_OAEP_PADDING) <= 0) {
		return 11;
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx_dec_proxy, EVP_sha256()) <= 0) {
		return 12;
	}
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx_dec_proxy, EVP_sha256()) <= 0) {
		return 13;
	}

	rsa_proxy_initialized = true;
	return 1;
}

int Crypto::rsa_set_private_key_proxy(unsigned char* privatekey, size_t privatekey_len) {

	const unsigned char* privatekey_const = reinterpret_cast<const unsigned char*>(privatekey);

	if (rsa_proxy_initialized) {
		EVP_PKEY_free(rsa_keys_proxy); // Free possible previous session
		EVP_PKEY_CTX_free(rsa_ctx_dec_proxy);
		rsa_proxy_initialized = false;
	}


	// Load private key
	if (!(rsa_keys_proxy = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &privatekey_const, privatekey_len))) {
		return 10;
	}

	if (!(rsa_ctx_dec_proxy = EVP_PKEY_CTX_new(rsa_keys_proxy, NULL))) {
		return 11;
	}

	// Set decryption context

	if (EVP_PKEY_decrypt_init(rsa_ctx_dec_proxy) != 1) {
		return 12;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(rsa_ctx_dec_proxy, RSA_PKCS1_OAEP_PADDING) <= 0) {
		return 13;
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx_dec_proxy, EVP_sha256()) <= 0) {
		return 14;
	}
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx_dec_proxy, EVP_sha256()) <= 0) {
		return 15;
	}

	rsa_proxy_initialized = true;
	return 1;
}



// Returns the proxy RSA public key in the publickey buffer, as well as the size of the public key
int Crypto::rsa_get_public_key_proxy(unsigned char* publickey, size_t publickey_len) {
	if (publickey_len < 256) { // Using RSA2048, thus key size 256 bytes
		return 10;
	}

	if (!rsa_proxy_initialized) {
		return 11;
	}

	BIO* bio = BIO_new(BIO_s_mem());
	if (PEM_write_bio_PUBKEY(bio, rsa_keys_proxy) != 1) {
		return 12;
	}

	int key_size = BIO_pending(bio);
	if (BIO_read(bio, publickey, key_size) != key_size) {
		return 13;
	}
	publickey_len = key_size;

	// Cleanup the BIO object
	BIO_free_all(bio);
	return 1;
}

int Crypto::rsa_session_client(unsigned char* publickey_client, size_t publickey_client_len) {
	// Load the RSA public key
	BIO* bio = BIO_new_mem_buf(publickey_client, publickey_client_len);
	if (!bio) {
		return 10;
	}
	if (rsa_client_initialized) {
		EVP_PKEY_free(rsa_keys_client); // Clean up previous key; if no key set before, does nothing
		EVP_PKEY_CTX_free(rsa_ctx_enc_client); // Clean up previous key; if no key set before, does nothing
		rsa_client_initialized = false;
	}

	rsa_keys_client = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!rsa_keys_client) {
		return 11;
	}

	BIO_free_all(bio);



	// Set encryption context
	if (!(rsa_ctx_enc_client = EVP_PKEY_CTX_new(rsa_keys_client, NULL))) {
		return 12;
	}

	if (EVP_PKEY_encrypt_init(rsa_ctx_enc_client) != 1) {
		return 13;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(rsa_ctx_enc_client, RSA_PKCS1_OAEP_PADDING) <= 0) {
		return 14;
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(rsa_ctx_enc_client, EVP_sha256()) <= 0) {
		return 15;
	}
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(rsa_ctx_enc_client, EVP_sha256()) <= 0) {
		return 16;
	}

	rsa_client_initialized = true;
	return 1;
}

int Crypto::rsa_encrypt_client(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len) {
	if (!rsa_ctx_enc_client) {
		return 10;
	}

	if (EVP_PKEY_encrypt(rsa_ctx_enc_client, result, result_len, data, data_len) != 1) {
		return 11;
	}
	return 1;
}

int Crypto::rsa_decrypt_proxy(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len) {
	if (!rsa_ctx_dec_proxy) {
		return 10;
	}

	if (EVP_PKEY_decrypt(rsa_ctx_dec_proxy, result, result_len, data, data_len) != 1) {
		//return 11;
	}
	return 1;
}




/*********** AES ************/
// Set the AES private key of the session with the database
int Crypto::aes_set_key_db(unsigned char* key_db, size_t key_db_len) {
	//RAND_bytes(aes_key_db, sizeof(aes_key_db));

	if (aes_db_initialized) {
		EVP_CIPHER_CTX_free(aes_ctx_enc_db);
		EVP_CIPHER_CTX_free(aes_ctx_dec_db);
		aes_db_initialized = false;
	}

	// Set DB root key
	if (sizeof(root_key_db) != key_db_len) {
		return 10;
	}
	memcpy(root_key_db, key_db, key_db_len);

	// Set DB AES encryption key
	std::vector<unsigned char> enc_key_salt(228, 0);
	memcpy(enc_key_salt.data(), u"Microsoft SQL Server cell encryption key with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256", 228); // Copy without null terminator byte
	unsigned int enc_key_len_real = 0;
	if (!(HMAC(EVP_sha256(), root_key_db, 32, enc_key_salt.data(), enc_key_salt.size(), aes_key_db, &enc_key_len_real))) {
		return 11;
	}

	if (enc_key_len_real <= 0) {
		return 12;
	}


	// Set DB AES MAC key
	std::vector<unsigned char> mac_key_salt(214, 0);
	memcpy(mac_key_salt.data(), u"Microsoft SQL Server cell MAC key with encryption algorithm:AEAD_AES_256_CBC_HMAC_SHA256 and key length:256", 214); // Copy without null terminator byte

	unsigned int mac_key_len_real = 0;
	if (!(HMAC(EVP_sha256(), root_key_db, 32, mac_key_salt.data(), mac_key_salt.size(), mac_key_db, &mac_key_len_real))) {
		return 13;
	}

	if (mac_key_len_real <= 0) {
		return 14;
	}

	// Initialize encryption context
	if (!(aes_ctx_enc_db = EVP_CIPHER_CTX_new())) {
		return 15;
	}

	// Initialize decryption context
	if (!(aes_ctx_dec_db = EVP_CIPHER_CTX_new())) {
		return 16;
	}

	aes_db_initialized = true;
	return 1;
}



int Crypto::aes_session_client(unsigned char* key, unsigned char* iv) {
	// Assuming the key and IV are of the correct predetermined length (key=32, IV=16 bytes)

	if (aes_client_initialized) {
		EVP_CIPHER_CTX_free(aes_ctx_dec_client); // Free any previous session
		aes_client_initialized = false;
	}

	// Initialize decryption context
	if (!(aes_ctx_dec_client = EVP_CIPHER_CTX_new())) {
		return 12;
	}

	memcpy(aes_key_client, key, 32);
	memcpy(aes_iv_client, iv, 16);

	aes_client_initialized = true;
	return 1;
}

// Set new random values for aes key and IV for communication back to client
int Crypto::aes_session_client_backward() {

	if (aes_client_initialized_backward) {
		EVP_CIPHER_CTX_free(aes_ctx_enc_client); // Free any previous session
		aes_client_initialized_backward = false;
	}

	// Initialize encryption context
	if (!(aes_ctx_enc_client = EVP_CIPHER_CTX_new())) {
		return 10;
	}

	RAND_bytes(aes_iv_client_backward, 16); // Set new random IV for backward communication
	RAND_bytes(aes_key_client_backward, 32); // Set new random key for backward communication
	aes_client_initialized_backward = true;
	return 1;
}

// Encrypted the aes session key and IV towards the client public key
int Crypto::aes_get_session_client_encrypted(unsigned char* key, size_t key_len, unsigned char* iv, size_t iv_len) {
	if (!aes_client_initialized_backward) {
		return 10;
	}

	if (rsa_encrypt_client(aes_key_client_backward, 32, key, &key_len) != 1) {
		return 11;
	}
	if (rsa_encrypt_client(aes_iv_client_backward, 16, iv, &iv_len) != 1) {
		return 12;
	}

	return 1;
}

int Crypto::aes_encrypt_client(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len) {
	// TODO reusing IV for this session is less secure;

	// EVP_CIPHER_block_size(EVP_aes_256_cbc()) = 16
	int required_size = data_len + 16 - (data_len % 16);
	if (*result_len < required_size) {
		return 10;
	}

	if (!aes_client_initialized_backward) {
		return 11;
	}

	if (EVP_EncryptInit_ex(aes_ctx_enc_client, EVP_aes_256_cbc(), NULL, aes_key_client_backward, aes_iv_client_backward) != 1) {
		return 12;
	}

	// Encrypt the data
	int enc_length = 0;
	if (EVP_EncryptUpdate(aes_ctx_enc_client, result, &enc_length, data, data_len) != 1) {
		return 13;
	}

	int final_length = 0;
	if (EVP_EncryptFinal_ex(aes_ctx_enc_client, result + enc_length, &final_length) != 1) { // Final block (with padding)
		return 14;
	}
	enc_length += final_length;
	*result_len = enc_length;

	return 1;
}

int Crypto::aes_decrypt_client(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len) {
	if (*result_len < data_len) {
		return 10;
	}

	if (!aes_client_initialized) {
		return 11;
	}

	if (EVP_DecryptInit_ex(aes_ctx_dec_client, EVP_aes_256_cbc(), NULL, aes_key_client, aes_iv_client) != 1) {
		return 12;
	}

	// Decrypt the data
	int dec_length = 0;
	if (EVP_DecryptUpdate(aes_ctx_dec_client, result, &dec_length, data, data_len) != 1) {
		return 13;
	}

	int final_length = 0;
	if (EVP_DecryptFinal_ex(aes_ctx_dec_client, result + dec_length, &final_length) != 1) { // Final block (with padding)
		return 14;
	}
	dec_length += final_length;
	*result_len = dec_length;

	return 1;
}

// Encrypt towards the database with AES
// ciphertext = versionbyte + MAC + IV + aes_256_cbc_ciphertext
int Crypto::aes_encrypt_db(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len) {

	int required_size_ciphertext = data_len + 16 - (data_len % 16); // EVP_CIPHER_block_size(EVP_aes_256_cbc()) = 16
	if (*result_len < required_size_ciphertext + 1 + 32 + 16) { // We need enough space for the ciphertext, version byte, MAC, and IV
		return 10;
	}

	if (!aes_db_initialized) {
		return 11;
	}

	unsigned char versionbyte = 0x01;

	// IV
	std::vector<unsigned char> iv(16, 0);
	RAND_bytes(iv.data(), iv.size()); // Use random IV for deterministic encryption

	// Encrypt the data
	std::vector<unsigned char> enc_data(required_size_ciphertext, 0);

	if (EVP_EncryptInit_ex(aes_ctx_enc_db, EVP_aes_256_cbc(), NULL, aes_key_db, iv.data()) != 1) {
		return 12;
	}

	int enc_length = 0;
	if (EVP_EncryptUpdate(aes_ctx_enc_db, enc_data.data(), &enc_length, data, data_len) != 1) {
		return 13;
	}

	int final_length = 0;
	if (EVP_EncryptFinal_ex(aes_ctx_enc_db, enc_data.data() + enc_length, &final_length) != 1) { // Final block (with padding)
		return 14;
	}
	enc_length += final_length;


	// MAC
	//mac = versionbyte + IV + Ciphertext + versionbyte_length
	size_t mac_data_len = 1 + 16 + enc_length + 1;
	std::vector<unsigned char> mac_data(mac_data_len, 0);


	mac_data[0] = 0x01; // versionbyte = 0x01
	memcpy(mac_data.data() + 1, iv.data(), 16); //iv
	memcpy(mac_data.data() + 1 + 16, enc_data.data(), enc_length); //ciphertext
	mac_data[1 + 16 + enc_length] = 1; // versionbyte_length = 1

	std::vector<unsigned char> mac(EVP_MAX_MD_SIZE);
	//unsigned char* mac = HMAC(EVP_sha256(), mac_key, 32, mac_data.data(), mac_data_len, nullptr, nullptr);
	unsigned int mac_len_real = 0;
	HMAC(EVP_sha256(), mac_key_db, 32, mac_data.data(), mac_data_len, mac.data(), &mac_len_real);
	mac.resize(mac_len_real);


	// Create complete buffer
	size_t buffer_len = 1 + 32 + 16 + enc_length;
	std::vector<unsigned char> buffer(buffer_len, 0);
	buffer[0] = versionbyte; //versionbyte
	memcpy(buffer.data() + 1, mac.data(), 32); //mac
	memcpy(buffer.data() + 1 + 32, iv.data(), 16); //iv
	memcpy(buffer.data() + 1 + 32 + 16, enc_data.data(), enc_length); // encrypted data


	memcpy(result, buffer.data(), buffer_len);
	*result_len = buffer_len;

	return 1;
}

// Decrypt from the database with AES
// ciphertext = versionbyte + MAC + IV + aes_256_cbc_ciphertext -> decrypt
int Crypto::aes_decrypt_db(unsigned char* data, size_t data_len, unsigned char* result, size_t* result_len) {
	if (*result_len < (data_len - 1 - 32 - 16)) {
		return 10;
	}

	if (!aes_db_initialized) {
		return 11;
	}

	// Extract MAC, IV, ciphertext from input

	std::vector<unsigned char> mac(32, 0);
	memcpy(mac.data(), data + 1, 32);

	std::vector<unsigned char> iv(16, 0);
	memcpy(iv.data(), data + 1 + 32, 16);

	size_t ciphertext_len = data_len - 1 - 32 - 16;
	std::vector<unsigned char> ciphertext(ciphertext_len, 0);
	memcpy(ciphertext.data(), data + 1 + 32 + 16, ciphertext_len);


	// MAC
	//mac = versionbyte + IV + Ciphertext + versionbyte_length
	size_t mac_data_len = 1 + 16 + ciphertext_len + 1;
	std::vector<unsigned char> mac_data(mac_data_len, 0);


	mac_data[0] = 0x01; // versionbyte = 0x01
	memcpy(mac_data.data() + 1, iv.data(), 16); //iv
	memcpy(mac_data.data() + 1 + 16, ciphertext.data(), ciphertext_len); //ciphertext
	mac_data[1 + 16 + ciphertext_len] = 1; // versionbyte_length = 1

	std::vector<unsigned char> mac_calculated(EVP_MAX_MD_SIZE);
	//unsigned char* mac = HMAC(EVP_sha256(), mac_key, 32, mac_data.data(), mac_data_len, nullptr, nullptr);
	unsigned int mac_len_real = 0;
	HMAC(EVP_sha256(), mac_key_db, 32, mac_data.data(), mac_data_len, mac_calculated.data(), &mac_len_real);
	mac_calculated.resize(mac_len_real);

	// compare the calculated hash with the given hash
	if (mac != mac_calculated) {
		return 12; // Integrity error, given mac does not correspond with calcuated mac
	}



	//std::vector<unsigned char> plain_data(data_len - 1 - 32 - 16, 0);

	// Decrypt the data
	if (EVP_DecryptInit_ex(aes_ctx_dec_db, EVP_aes_256_cbc(), NULL, aes_key_db, iv.data()) != 1) {
		return 13;
	}

	int dec_length = 0;
	if (EVP_DecryptUpdate(aes_ctx_dec_db, result, &dec_length, ciphertext.data(), ciphertext_len) != 1) {
		return 14;
	}


	int final_length = 0;
	if (EVP_DecryptFinal_ex(aes_ctx_dec_db, result + dec_length, &final_length) != 1) { // Final block (with padding)
		return 15;
	}
	dec_length += final_length;
	*result_len = dec_length;

	return 1;
}