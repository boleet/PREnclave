#include "pch.h"
#include "PREnclaveLink.h"
#include "PREnclaveLinkManaged.h"
#include <Windows.h>
#include <string>
#include <iostream>


PREnclaveLinkManaged::PREnclaveLinkManaged()
{
	native = new PREnclaveLinkNative();
}

PREnclaveLinkManaged::~PREnclaveLinkManaged()
{
	native->~PREnclaveLinkNative();
	native = nullptr;
}

int PREnclaveLinkManaged::enclave_hello()
{
	int rv;
	rv = native->enclave_hello();
	return rv;
}

int PREnclaveLinkManaged::enclave_session(array<System::Byte>^ key_enc, array<System::Byte>^ iv_enc, array<System::Byte>^ publickey_client) {
	int rv;
	pin_ptr<System::Byte> key_enc_buf = &key_enc[0];
	pin_ptr<System::Byte> iv_enc_buf = &iv_enc[0];
	pin_ptr<System::Byte> publickey_client_buf = &publickey_client[0];
	rv = native->enclave_session(key_enc_buf, key_enc->Length, iv_enc_buf, iv_enc->Length, publickey_client_buf, publickey_client->Length);
	return rv;
}

int PREnclaveLinkManaged::enclave_get_session_client(array<System::Byte>^ key_enc, array<System::Byte>^ iv_enc) {
	int rv;
	pin_ptr<System::Byte> key_enc_buf = &key_enc[0];
	pin_ptr<System::Byte> iv_enc_buf = &iv_enc[0];
	rv = native->enclave_get_session_client(key_enc_buf, key_enc->Length, iv_enc_buf, iv_enc->Length);
	return rv;
}

int PREnclaveLinkManaged::enclave_PREForward(array<System::Byte>^ data, array<System::Byte>^ result)
{
	int rv;
	pin_ptr<System::Byte> data_buffer = &data[0];
	pin_ptr<System::Byte> result_buffer = &result[0];
	rv = native->enclave_PREForward(data_buffer, data->Length, result_buffer, result->Length);
	return rv;
}

int PREnclaveLinkManaged::enclave_PREBackward(array<System::Byte>^ data, array<System::Byte>^ result)
{
	int rv;
	pin_ptr<System::Byte> data_buffer = &data[0];
	pin_ptr<System::Byte> result_buffer = &result[0];
	rv = native->enclave_PREBackward(data_buffer, data->Length, result_buffer, result->Length);
	return rv;
}

int PREnclaveLinkManaged::enclave_set_key_db_insecure(array<System::Byte>^ key_db) {
	int rv;
	int input_length = key_db->Length;
	pin_ptr<System::Byte> key_db_buffer = &key_db[0];
	rv = native->enclave_set_key_db_insecure(key_db_buffer, input_length);
	return rv;
}


int PREnclaveLinkManaged::enclave_set_private_key_proxy_insecure(array<System::Byte>^ privatekey) {
	int rv;
	int input_length = privatekey->Length;
	pin_ptr<System::Byte> privatekey_buffer = &privatekey[0];
	rv = native->enclave_set_private_key_proxy_insecure(privatekey_buffer, input_length);
	return rv;
}

int PREnclaveLinkManaged::enclave_get_public_key_proxy(array<System::Byte>^ publickey) {
	int rv;
	int input_length = publickey->Length;
	pin_ptr<System::Byte> publickey_buffer = &publickey[0];
	rv = native->enclave_get_public_key_proxy(publickey_buffer, input_length);
	return rv;
}