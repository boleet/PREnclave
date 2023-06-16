# PREnclaveSGX
[Proxy Re-Encryption](https://en.wikipedia.org/wiki/Proxy_re-encryption) (PRE) implemented in an [Intel SGX](https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html) Enclave to be used together with Microsoft SQL [Always Encrypted](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-enclaves?view=sql-server-ver16).

Note that this project is for **demonstration purposes only**, and should **not be consider secure**! Code provided only serves as a proof-of-concept. 
Limitations of this prototype include (but are not limited to):
- the proxy RSA private key is hardcoded for simplicity. In the end we would like to remote attest the enclave from a seperate trusted computer, set-up a secure channel, and transmit the private key over that secure channel. Alternatively, the proxy enclave could generate the RSA private key itself, and allow the public key to be exported (the latter funcionality is already implemented). This however means that the private key changes every time the enclave is (re)started.
- the database AES private key is provided to the enclave from the untrusted program. In the end we would like to remote attest the enclave from a sepearte trusted computer, set-up a secure channel, and transmit the secret key over that secure channel.
- The client-proxy session from the request is reused in the response. In the end we would like to re-generate the session key and IV, and send it back along with the encrypted data.

## Architecture
In a set-up with a client application, API server, and database server the goal is to eliminate plain-text on both the API server as well as on the database server. For the latter, Microsoft SQL Always Encrypted can be used. To also eliminate plaintexts on the API server, proxy re-encryption is used.
In short, the client sends encrypted query parameters to the API server, which re-encrypts (in an trusted execution environment) the parameters before sending to the SQL Server. The SQL Server uses Always Encrypted to search through the encrypted data, after which the encrypted query results are send back the the API server. The API server re-encrypts (in an TEE) the response towards the client.
Assuming the security of the Intel SGX Trusted Execution Environment, no plaintext is available on both the API and database server at rest, in use, or in transit.


The forward direction receives data form the client and encrypts this towards the database. The PREnclave receives AES encrypted data, the encrypted session key , and the encrypted IV (both encrypted using RSA toward the proxy public key), such that it internal decrypts the received data. Then the data is encrypted for use in Microsoft SQL Always Encrypted, following the [defined cryptography](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-cryptography?view=sql-server-ver16).
The backward direction receives data from the database (encrypted under the Column Encryption Key) and the public key of the client. Internally the data is decrypted, and encrypted using a session key toward the client. The session key and IV are encrypted as well (towards the client public RSA key).


In the figure below, this project is the TEE Re-encrypt part, at the center left.
![AEPRETEE](https://user-images.githubusercontent.com/52708576/235639893-2249f8c5-4eb8-4e1b-919f-2ed89b4e0330.png)

## Implementation
The enclave is implemented in C++ and can be called from dotnet/C# using the provided bridge functions. The enclave has dependencies on [intel-sgx-ssl](https://github.com/intel/intel-sgx-ssl) and the [Intel SGX SDK](https://www.intel.com/content/www/us/en/developer/articles/guide/getting-started-with-sgx-sdk-for-windows.html). The code has been developed and tested on Windows 10.0.19044 with Visual Studio 2022 (while the enclave are Visual Studio 2019 projects).

### PREnclaveSGX
The PREnclave project, which consist of the enclave itself as well as bridge functions to bridge between managed C# and unmanged C++ code (see [this](https://www.intel.com/content/www/us/en/developer/articles/technical/using-enclaves-with-callbacks-via-ocalls.html) for details).
- PREnclaveSGX: the enclave code, written in C++
- EnclaveBridge: the bridge functions in C
- EnclaveLink: the link functions with Common Language Runtime, responsible for converting unmanaged and managed data.

### TesterPREnclaveSGX
A dotnet console program that calls all enclave functions. Can be used to demonstrate the functionality of the enclave.


## Instalation (Windows)
1. Install Visual Studio and Intel SGX SDK and PSW, via (these)[[https://www.intel.com/content/www/us/en/developer/articles/guide/getting-started-with-sgx-sdk-for-windows.html]] instructions under 'Installing Development SW'
1. Make sure the Intel.SGX.SDK nuget package is installed in the project.




### How this project has been set-up
Summary of how this project has been set-up. No need to repeat these actions. The steps in the SGX SDK Developer Reference for Windows OS have been followed.

1. Create PREnclave project using the wizard in Visual Studio 2019 (SGX SDK > plugin > vs2019 > install .vsix files) with the default settings.
1. Use Intel (intel-sgx-ssl)[https://github.com/intel/intel-sgx-ssl] library 
    1. Build the library and add to the packages folder. 
    1. Edit the project properties to include the ssl library, as stated in the SGX SSL Developer Guide.
1. PREnclaveBridge
    1. Create the PREnclaveBridge project as a Dynamic-Link Library.
    1. Add the EDL file to the bridge project (in VS2019)
	1. Configure the SGX SDK and ssl library as per the instructions from the manual, where this is the 'untrusted application'.
1. PREnclaveLink
    1. Create the PREnclaveLink project as a CLR Class Library (.NET)
	1. Add PREnclaveLinkManaged and PREnclaveLinkNative classes
	1. Change project properties
	    1. Advanced > Common Language Runtime Support > Common Language Runtime Support (/clr)
	    1. C/C++ > General > Additional Include Directories > add "$(SolutionDir)PREnclaveBridge"
		1. Linker > Input > Additional Dependencies > add "PREnclaveBridge.lib"
1. Add the SGXSDKInstallPath user macro to the bridge and link projects via the Property Manager window
1. PREnclaveTester
    1. Create project as a DotNet console application
	1. Add PREnclaveLink as a reference
	1. Change project properties > Debug > General > Open debug launch profiles UI > Working Directory > specify the build directory (x64 in root directory)
	1. Change project settings > Build > General > Platform target > x64
	1. Set this console application as the startup project of the solution
	
	
	
	
	





