#pragma once
#include "PREnclaveLink.h"
#include "PREnclaveLinkManaged.h"
#include <sgx_urts.h>

class PRENCLAVELINK_API PREnclaveLinkNative {
	friend ref class PREnclaveLinkManaged;

	void* managed;

protected:
	sgx_enclave_id_t eid = 0;
	sgx_launch_token_t token = { 0 };
	HANDLE hmutex;
	int launched = 0;

	int get_enclave(sgx_enclave_id_t* id);
	int enclave_hello();
	int enclave_PREForward(unsigned char* data, size_t data_len, unsigned char* result, size_t result_len);
	int enclave_PREBackward(unsigned char* data, size_t data_len, unsigned char* result, size_t result_len);
	int enclave_session(unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len, unsigned char* publickey_client, size_t publickey_client_len);
	int enclave_get_session_client(unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len);
	int enclave_set_key_db_insecure(unsigned char* key_db, size_t key_db_len);
	int enclave_set_private_key_proxy_insecure(unsigned char* privatekey, size_t privatekey_len);
	int enclave_get_public_key_proxy(unsigned char* publickey, size_t publickey_len);

public:
	PREnclaveLinkNative(void);
	~PREnclaveLinkNative(void);
};
