#pragma once
#include <sgx_urts.h>
#include <tchar.h>
#include <functional>

#ifdef ENCLAVENATIVE_API_EXPORTING
#define ENCLAVENATIVE_API __declspec(dllexport)
#else
#define ENCLAVENATIVE_API __declspec(dllimport)
#endif

#define ENCLAVE_FILE _T("PREnclave.signed.dll") 

extern "C" {

	ENCLAVENATIVE_API sgx_status_t en_create_enclave(sgx_launch_token_t* token, sgx_enclave_id_t* eid, int* updated);
	ENCLAVENATIVE_API sgx_status_t en_destroy_enclave(sgx_enclave_id_t eid);

	ENCLAVENATIVE_API sgx_status_t en_hello(sgx_enclave_id_t eid, int* rv);
	ENCLAVENATIVE_API sgx_status_t en_initialize(sgx_enclave_id_t eid, int* rv);
	ENCLAVENATIVE_API sgx_status_t en_session(sgx_enclave_id_t eid, int* rv, unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len, unsigned char* publickey_client, size_t publickey_client_len);
	ENCLAVENATIVE_API sgx_status_t en_get_session_client(sgx_enclave_id_t eid, int* rv, unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len);
	ENCLAVENATIVE_API sgx_status_t en_PREForward(sgx_enclave_id_t eid, int* rv, unsigned char* data, size_t data_len, unsigned char* result, size_t result_len);
	ENCLAVENATIVE_API sgx_status_t en_PREBackward(sgx_enclave_id_t eid, int* rv, unsigned char* data, size_t data_len, unsigned char* result, size_t result_len);
	ENCLAVENATIVE_API sgx_status_t en_set_key_db_insecure(sgx_enclave_id_t eid, int* rv, unsigned char* key_db, size_t key_db_len);
	ENCLAVENATIVE_API sgx_status_t en_set_private_key_proxy_insecure(sgx_enclave_id_t eid, int* rv, unsigned char* privatekey, size_t privatekey_len);
	ENCLAVENATIVE_API sgx_status_t en_get_public_key_proxy(sgx_enclave_id_t eid, int* rv, unsigned char* publickey, size_t publickey_len);
};
