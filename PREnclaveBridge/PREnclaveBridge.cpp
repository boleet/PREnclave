#include "pch.h"
#define ENCLAVENATIVE_API_EXPORTING 1

#include <sgx_urts.h>
#include <tchar.h>
#include <string.h>
#include <Windows.h>
#include "PREnclaveBridge.h"
#include "PREnclave_u.h"


ENCLAVENATIVE_API sgx_status_t en_create_enclave(sgx_launch_token_t* token, sgx_enclave_id_t* eid, int* updated)
{
	return sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, token, updated, eid, NULL);
}

ENCLAVENATIVE_API sgx_status_t en_destroy_enclave(sgx_enclave_id_t eid)
{
	return sgx_destroy_enclave(eid);
}

ENCLAVENATIVE_API sgx_status_t en_hello(sgx_enclave_id_t eid, int* rv)
{
	return e_hello(eid, rv);
}

ENCLAVENATIVE_API sgx_status_t en_initialize(sgx_enclave_id_t eid, int* rv)
{
	return e_initialize(eid, rv);
}

ENCLAVENATIVE_API sgx_status_t en_session(sgx_enclave_id_t eid, int* rv, unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len, unsigned char* publickey_client, size_t publickey_client_len)
{
	return e_session(eid, rv, key_enc, key_enc_len, iv_enc, iv_enc_len, publickey_client, publickey_client_len);
}

ENCLAVENATIVE_API sgx_status_t en_get_session_client(sgx_enclave_id_t eid, int* rv, unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len)
{
	return e_get_session_client(eid, rv, key_enc, key_enc_len, iv_enc, iv_enc_len);
}

ENCLAVENATIVE_API sgx_status_t en_PREForward(sgx_enclave_id_t eid, int* rv, unsigned char* data, size_t data_len, unsigned char* result, size_t result_len)
{
	return e_PREForward(eid, rv, data, data_len, result, result_len);
}

ENCLAVENATIVE_API sgx_status_t en_PREBackward(sgx_enclave_id_t eid, int* rv, unsigned char* data, size_t data_len, unsigned char* result, size_t result_len)
{
	return e_PREBackward(eid, rv, data, data_len, result, result_len);
}

ENCLAVENATIVE_API sgx_status_t en_set_key_db_insecure(sgx_enclave_id_t eid, int* rv, unsigned char* key_db, size_t key_db_len) {
	return e_set_key_db_insecure(eid, rv, key_db, key_db_len);
}

ENCLAVENATIVE_API sgx_status_t en_set_private_key_proxy_insecure(sgx_enclave_id_t eid, int* rv, unsigned char* privatekey, size_t privatekey_len)
{
	return e_set_private_key_proxy_insecure(eid, rv, privatekey, privatekey_len);
}

ENCLAVENATIVE_API sgx_status_t en_get_public_key_proxy(sgx_enclave_id_t eid, int* rv, unsigned char* publickey, size_t publickey_len)
{
	return e_get_public_key_proxy(eid, rv, publickey, publickey_len);
}