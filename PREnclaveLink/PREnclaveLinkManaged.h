#pragma once

#include "pch.h"
#include "PREnclaveLink.h"
#include "PREnclaveLinkNative.h"

public ref class PREnclaveLinkManaged
{
	PREnclaveLinkNative* native;

public:
	PREnclaveLinkManaged();
	~PREnclaveLinkManaged();

	int enclave_hello();
	int enclave_PREForward(array<System::Byte>^ data, array<System::Byte>^ result);
	int enclave_PREBackward(array<System::Byte>^ data, array<System::Byte>^ result);
	int enclave_session(array<System::Byte>^ key_enc, array<System::Byte>^ iv_enc, array<System::Byte>^ publickey_client);
	int enclave_get_session_client(array<System::Byte>^ key_enc, array<System::Byte>^ iv_enc);
	int enclave_set_key_db_insecure(array<System::Byte>^ key_db);
	int enclave_set_private_key_proxy_insecure(array<System::Byte>^ privatekey);
	int enclave_get_public_key_proxy(array<System::Byte>^ publickey);
};