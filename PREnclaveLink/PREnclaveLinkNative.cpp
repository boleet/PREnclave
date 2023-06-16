#include "pch.h"

#include "PREnclaveLink.h"
#include "PREnclaveLinkNative.h"
#include <sgx_urts.h>
#include "PREnclaveBridge.h"
#include "PREnclaveLinkManaged.h"
#include <functional>
#include <string>
#include <iostream>

#pragma unmanaged

using namespace System;
using namespace System::Threading;
using namespace System::Runtime::InteropServices;
using namespace std;


PREnclaveLinkNative::PREnclaveLinkNative(void)
{
	hmutex = CreateMutex(NULL, FALSE, L"Enclave");

	// Initialize the enclave
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	int x = get_enclave(&thiseid);
	if (x) { // This automatically launches the enclave if not exists
		status = en_initialize(thiseid, &rv); // call enclave bridge function
		if (status != SGX_SUCCESS || rv != 1) {
			cout << "PREnclaveLinkNative: call to en_initialize failed with status code ";
			cout << status;
			cout << "\n";
		}
	}
	else {
		cout << "PREnclaveLinkNative: get_enclave() failed during initialization: ";
		cout << x;
		cout << "\n";
	}
}

PREnclaveLinkNative::~PREnclaveLinkNative(void)
{
	if (WaitForSingleObject(hmutex, INFINITE) != WAIT_OBJECT_0) return;

	if (launched) en_destroy_enclave(eid);
	eid = 0;
	launched = 0;
	ReleaseMutex(hmutex);

	//cout << "PREnclaveLinkNative: destructor called, destroyed enclave!\n";
}


int PREnclaveLinkNative::get_enclave(sgx_enclave_id_t* id)
{
	int rv = 1;
	int updated = 0;

	if (WaitForSingleObject(hmutex, INFINITE) != WAIT_OBJECT_0) {
		cout << "get_enclave error: waiting for mutex\n";
		return 0;
	}

	if (launched) {
		*id = eid;
	}
	else {
		sgx_status_t status;
		status = en_create_enclave(&token, &eid, &updated);
		if (status == SGX_SUCCESS) {
			*id = eid;
			rv = 1;
			launched = 1;
			//cout << "PREnclaveLinkNative: created enclave!\n";
		}
		else {
			rv = 0;
			launched = 0;
			cout << "get_enclave error: could not create enclave: ";
			cout << status;
			cout << "\n";
		}
	}
	ReleaseMutex(hmutex);
	return rv;
}

int PREnclaveLinkNative::enclave_hello()
{
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_hello(thiseid, &rv); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}

int PREnclaveLinkNative::enclave_session(unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len, unsigned char* publickey_client, size_t publickey_client_len) {
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_session(thiseid, &rv, key_enc, key_enc_len, iv_enc, iv_enc_len, publickey_client, publickey_client_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}


int PREnclaveLinkNative::enclave_get_session_client(unsigned char* key_enc, size_t key_enc_len, unsigned char* iv_enc, size_t iv_enc_len) {
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_get_session_client(thiseid, &rv, key_enc, key_enc_len, iv_enc, iv_enc_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}

int PREnclaveLinkNative::enclave_PREForward(unsigned char* data, size_t data_len, unsigned char* result, size_t result_len)
{
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_PREForward(thiseid, &rv, data, data_len, result, result_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}

int PREnclaveLinkNative::enclave_PREBackward(unsigned char* data, size_t data_len, unsigned char* result, size_t result_len)
{
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_PREBackward(thiseid, &rv, data, data_len, result, result_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}




int PREnclaveLinkNative::enclave_set_key_db_insecure(unsigned char* key_db, size_t key_db_len) {
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_set_key_db_insecure(thiseid, &rv, key_db, key_db_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}

int PREnclaveLinkNative::enclave_set_private_key_proxy_insecure(unsigned char* privatekey, size_t privatekey_len) {
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_set_private_key_proxy_insecure(thiseid, &rv, privatekey, privatekey_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}

int PREnclaveLinkNative::enclave_get_public_key_proxy(unsigned char* publickey, size_t publickey_len) {
	int rv = 0;
	sgx_status_t status;
	sgx_enclave_id_t thiseid;

	if (!get_enclave(&thiseid)) return 99;

	// Retry if we lose the enclave due to a power transition
again:
	status = en_get_public_key_proxy(thiseid, &rv, publickey, publickey_len); // call enclave bridge function
	switch (status) {
	case SGX_SUCCESS:
		return rv;
	case SGX_ERROR_ENCLAVE_LOST:
		if (get_enclave(&thiseid)) goto again;
	}

	return 98;
}