using System.Security.Cryptography;
using System.Text;

namespace TesterPREnclaveSGX
{
    internal class FunctionalTests
    {
        PREnclaveLinkManaged enclave;
        RSA rsa_client;
        byte[] rsa_client_publickey_bytes;
        RSA rsa_api;
        RSA rsa_api_secretkeygen; // only use to generate a proxy private key to sent to the enclave (note: insecure); different from the one above to make sure our untrusted proxy (rsa_api) does not have access to the keys within the enclave
        Aes aes_client;

        bool debug = false;

        public FunctionalTests(bool debug)
        {
            this.rsa_client = RSA.Create();
            this.rsa_client_publickey_bytes = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            this.rsa_api = RSA.Create();
            this.rsa_api_secretkeygen = RSA.Create();
            this.debug = debug;
        }

        public void TestAll()
        {
            Setup();
            TestSetPrivateRSAKey();
            TestGetPublicRSAKey();
            TestSetSession();
            TestSetDBKey();
            byte[] inpbytes = PreparePREForwardClient("testvalue");
            byte[] resforward = TestPREForward(inpbytes);
            byte[] resbackward = TestPREBackward(resforward);
            byte[] resbackwardatclient = TestPREBackwardClient(resbackward);
        }

        public void TestMemoryLeaks()
        {
            Setup();
            TestSetPrivateRSAKey();
            TestGetPublicRSAKey();
            TestSetSessionLoop(500);
        }

        private void TestPrint(string msg)
        {
            if (this.debug)
            {
                Console.WriteLine(msg);
            }
        }
        private void TestPrint(string template, string value)
        {
            if (this.debug)
            {
                Console.WriteLine(template, value);
            }
        }


        public void DebugFullRun()
        {
            int pre_amount = 10000;
            Console.WriteLine("Debuggin full run with amount " + pre_amount);


            /// PREPARE
            List<byte[]> PREInputs = new List<byte[]>();
            List<string> PREInputs_plainstring = new List<string>();
            RSA rsa_client_full = RSA.Create();


            RSA rsa_api_secretkeygen_full = RSA.Create(); // Actually this is performed on the server, but in the end we want to eliminate this at all; therefore we put it outside of the benchmark
            byte[] rsa_api_secretkey_full = rsa_api_secretkeygen_full.ExportPkcs8PrivateKey();

            Aes aes_client_full = Aes.Create();
            aes_client_full.Mode = CipherMode.CBC;
            byte[] key_enc_full = rsa_api_secretkeygen_full.Encrypt(aes_client_full.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] iv_enc_full = rsa_api_secretkeygen_full.Encrypt(aes_client_full.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] pk_client_full = Encoding.UTF8.GetBytes(rsa_client_full.ExportSubjectPublicKeyInfoPem());


            // Generate random inputs
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const int input_size = 20;
            for (int i = 0; i < pre_amount; i++)
            {
                string val = new string(Enumerable.Repeat(chars, input_size).Select(s => s[random.Next(s.Length)]).ToArray());
                PREInputs_plainstring.Add(val);
                PREInputs.Add(aes_client_full.EncryptCbc(Encoding.UTF8.GetBytes(val), aes_client_full.IV));
            }




            /// RUN


            // Create Enclave
            PREnclaveLinkManaged enclave_full = new PREnclaveLinkManaged();

            // Set RSA private key
            int eres_setprivatekeyproxy = enclave_full.enclave_set_private_key_proxy_insecure(rsa_api_secretkey_full);
            if (eres_setprivatekeyproxy != 1)
            {
                Console.WriteLine("Error: set private key proxy");
            }

            // Set client session
            int eres_createsession = enclave_full.enclave_session(key_enc_full, iv_enc_full, pk_client_full);
            if (eres_createsession != 1)
            {
                Console.WriteLine("Error: setting enclave session");
            }

            // Check the session (encrypted towards public key of the client)
            byte[] sesskey = new byte[256];
            byte[] sessIV = new byte[256];
            int eres_getsession = enclave_full.enclave_get_session_client(sesskey, sessIV);
            if (eres_getsession != 1)
            {
                Console.WriteLine("Error: getting enclave session");
            }
            Array.Resize(ref sesskey, Array.FindLastIndex(sesskey, b => b != 0) + 1);
            Array.Resize(ref sessIV, Array.FindLastIndex(sessIV, b => b != 0) + 1);

            //**** START CLIENT CODE ****//
            byte[] sesskeyplain = rsa_client_full.Decrypt(sesskey, RSAEncryptionPadding.OaepSHA256);
            byte[] sessIVplain = rsa_client_full.Decrypt(sessIV, RSAEncryptionPadding.OaepSHA256);
            //TestPrint("Client session decrypted at client [{0}]", string.Join(", ", sesskeyplain));
            //TestPrint("Client iv decrypted at client [{0}]", string.Join(", ", sessIVplain));

            Aes aes_client2 = Aes.Create();
            aes_client2.Mode = CipherMode.CBC;
            aes_client2.Key = sesskeyplain;
            aes_client2.IV = sessIVplain;
            //**** END CLIENT CODE ****//



            // Set database key
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            int eres_setdbkey = enclave_full.enclave_set_key_db_insecure(fakekey);
            if (eres_setdbkey != 1)
            {
                Console.WriteLine("Error: set key db");
            }

            List<byte[]> PREresults = new List<byte[]>();

            for (int i = 0; i < pre_amount; i++)
            {
                byte[] data_preforward = PREInputs[i];
                byte[] result_preforward = new byte[1 + 32 + 16 + data_preforward.Length]; // length = versionbyte (1) + MAC (32) + IV (16) + encrypted data size
                int eres_prenclaveforward = enclave_full.enclave_PREForward(data_preforward, result_preforward);
                if (eres_prenclaveforward != 1)
                {
                    Console.WriteLine("Error: pre forward " + i);
                }
                PREresults.Add(result_preforward);
            }

            List<byte[]> PREBackwardresults = new List<byte[]>();
            for (int i = 0; i < pre_amount; i++)
            {
                byte[] data_prebackward = PREresults[i];
                byte[] result_prebackward = new byte[data_prebackward.Length];
                int eres_prenclavebackward = enclave_full.enclave_PREBackward(data_prebackward, result_prebackward);
                if (eres_prenclavebackward != 1)
                {
                    Console.WriteLine("Error: pre backward " + i);
                }
                int first_zerobyte = Array.FindLastIndex(result_prebackward, b => b != 0);
                Array.Resize(ref result_prebackward, first_zerobyte + (32 - (first_zerobyte % 32)));
                PREBackwardresults.Add(result_prebackward);



            }

            enclave_full.Dispose();



            // Check integrity
            for (int i = 0; i < pre_amount; i++)
            {
                //TestPrint("backward result size " + PREBackwardresults[i].Length);
                //**** START CLIENT CODE ****//
                byte[] prebackwardplain = aes_client2.DecryptCbc(PREBackwardresults[i], aes_client2.IV);
                string prebackwardplainstring = Encoding.UTF8.GetString(prebackwardplain);
                //TestPrint("Decrypted bytes at client: [{0}]", string.Join(", ", prebackwardplain));
                //TestPrint("Try decoding the decrypted string: " + Encoding.UTF8.GetString(prebackwardplain));
                //**** END CLIENT CODE ****//

                if (prebackwardplainstring != PREInputs_plainstring[i])
                {
                    TestPrint("ERROR: input does not match output " + i);
                }
                else
                {
                    //TestPrint("Result check passed " + i);
                }
            }


        }











        // Initialize an enclave
        public void Setup()
        {
            // Initialize enclave manager and enclave
            TestPrint("Hi! Lets start with initializing the enclave manager and its enclave...");
            enclave = new PREnclaveLinkManaged(); // Creates an enclave manager, which creates an enclave

            // Call hello world, which returns a (secret :P) integer from the enclave.
            int a = enclave.enclave_hello();
            TestPrint("Result hello() printed from untrusted: " + a);
            TestPrint("");
        }

        // Set enclave proxy private RSA key
        // For simplicity we do this from untrusted code, which destroys our security guarantees
        // In the end, we would like to set-up a secure channel with remote attestation from another (trusted) device, and transmit the key over that secure channel
        public bool TestSetPrivateRSAKey()
        {
            byte[] rsa_api_secretkey = rsa_api_secretkeygen.ExportPkcs8PrivateKey();
            int eres_setprivatekeyproxy = enclave.enclave_set_private_key_proxy_insecure(rsa_api_secretkey);
            TestPrint("Setting RSA private key for proxy: " + eres_setprivatekeyproxy);
            if (eres_setprivatekeyproxy != 1) { return false; }

            return true;
        }

        // Get enclave proxy public RSA key
        public bool TestGetPublicRSAKey()
        {
            // Get public key from proxy (enclave)
            byte[] result_proxy_publickey = new byte[1024];
            int eres_getpublickeyproxy = enclave.enclave_get_public_key_proxy(result_proxy_publickey);
            TestPrint("Getting public key from enclave: " + eres_getpublickeyproxy + "=");
            if (eres_getpublickeyproxy != 1) { return false; }
            Array.Resize(ref result_proxy_publickey, Array.FindLastIndex(result_proxy_publickey, b => b != 0) + 1);

            // Set the public key of our rsa_api object, such that we can encrypt messages toward the proxy
            String result_proxy_publickey_string = Encoding.UTF8.GetString(result_proxy_publickey).Replace("-----BEGIN PUBLIC KEY-----\n", "").Replace("-----END PUBLIC KEY-----\n", "").ReplaceLineEndings("");
            byte[] reult_proxy_publickey_bytes = System.Convert.FromBase64String(result_proxy_publickey_string);
            rsa_api.ImportSubjectPublicKeyInfo(reult_proxy_publickey_bytes, out _);

            return true;
        }

        // The client prepares and AES session, encrypts the key and IV (toward proxy public key), and encrypts the query data
        public bool TestSetSession()
        {

            //**** START CLIENT CODE ****//
            aes_client = Aes.Create();
            aes_client.Mode = CipherMode.CBC;
            TestPrint("Client aes session key [{0}]", string.Join(", ", aes_client.Key));
            TestPrint("Client aes session iv [{0}]", string.Join(", ", aes_client.IV));

            TestPrint("Preparing key encapsulation, first bytes of plain key are: " + aes_client.Key[0] + "," + aes_client.Key[1] + "," + aes_client.Key[2] + "; and IV: " + aes_client.IV[0] + "," + aes_client.IV[1] + "," + aes_client.IV[2]);
            byte[] key_enc = rsa_api.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256); // Encrypt newly generated 
            byte[] iv_enc = rsa_api.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] pk_client = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            //**** END CLIENT CODE ****//

            // Proxy creates an session using the encrypted session key and IV, and the client public key (to encrypt results back to)
            TestPrint("create session key: " + Convert.ToBase64String(key_enc));
            TestPrint("create session IV: " + Convert.ToBase64String(iv_enc));
            TestPrint("create session pk client: " + Convert.ToBase64String(pk_client));
            int eres_createsession = enclave.enclave_session(key_enc, iv_enc, pk_client);
            TestPrint("Creating a session (encrypted key is " + key_enc[0] + "," + key_enc[1] + "," + key_enc[2] + "): " + eres_createsession);
            if (eres_createsession != 1) { return false; }
            TestPrint("");

            return true;
        }


        public bool TestSetSessionLoop(int amount)
        {

            //**** START CLIENT CODE ****//
            aes_client = Aes.Create();
            aes_client.Mode = CipherMode.CBC;

            byte[] key_enc = rsa_api.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256); // Encrypt newly generated 
            byte[] iv_enc = rsa_api.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] pk_client = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            //**** END CLIENT CODE ****//

            for (int i = 0; i < amount; i++)
            {
                // Proxy creates an session using the encrypted session key and IV, and the client public key (to encrypt results back to)
                TestPrint("Iteration " + i);
                int eres_createsession = enclave.enclave_session(key_enc, iv_enc, pk_client);
                if (eres_createsession != 1)
                {
                    TestPrint("Error!" + eres_createsession);
                    return false;
                }
            }


            return true;
        }




        // Set database key from here, which is insecure but simplifies the prototype
        // In the end, we would like to set-up a secure channel with remote attestation from another (trusted) device, and transmit the key over that secure channel
        public void TestSetDBKey()
        {
            Random rnd = new Random();
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            int eres_setdbkey = enclave.enclave_set_key_db_insecure(fakekey);
            TestPrint("Set db private key: " + eres_setdbkey);
            if (eres_setdbkey != 1) { return; }

        }


        // The client encrypts the value towards the proxy
        public byte[] PreparePREForwardClient(string input)
        {
            // The client encrypts the query input before sending to the proxy;
            //**** START CLIENT CODE ****//
            TestPrint("Lets call PREForward on the data: '" + input + "'");
            byte[] raw_input = Encoding.UTF8.GetBytes(input);
            byte[] data_preforward = aes_client.EncryptCbc(raw_input, aes_client.IV);
            //**** END CLIENT CODE ****//

            return data_preforward;
        }
        // Re-encrypt the given encrypted input bytes (under proxy RSA key) towards the database AES private key with Always Encryted structure
        public byte[] TestPREForward(byte[] data_preforward)
        {
            // The proxy only has access to the encrypted query parameter, and calls PREForward to encrypt towards the Always Encrypted Column
            byte[] result_preforward = new byte[1 + 32 + 16 + data_preforward.Length]; // length = versionbyte (1) + MAC (32) + IV (16) + encrypted data size
            int eres_prenclaveforward = enclave.enclave_PREForward(data_preforward, result_preforward);
            TestPrint("Result enclave_PREForward(): " + eres_prenclaveforward + " = ");
            if (eres_prenclaveforward != 1) { return null; }
            TestPrint("");

            return result_preforward;
        }


        public byte[] TestPREBackward(byte[] data_prebackward)
        {
            // PREBackward
            TestPrint("Lets call PREBackward on the PREForwarded data");
            byte[] result_prebackward = new byte[data_prebackward.Length];
            int eres_prenclavebackward = enclave.enclave_PREBackward(data_prebackward, result_prebackward);
            TestPrint("Result enclave_PREBackward(): " + eres_prenclavebackward + " = ");
            Array.Resize(ref result_prebackward, Array.FindLastIndex(result_prebackward, b => b != 0) + 1);
            if (eres_prenclavebackward != 1) { return null; }

            TestPrint("Try decoding the string: " + Encoding.UTF8.GetString(result_prebackward));
            TestPrint("");

            return result_prebackward;
        }

        // Re-encrypt the given encrypted data (under database Always Encrypted key and structure) towards the client session.
        public byte[] TestPREBackwardClient(byte[] result_prebackward)
        {
            // Check the session (encrypted towards public key of the client)
            byte[] sesskey = new byte[256];
            byte[] sessIV = new byte[256];
            int eres_getsession = enclave.enclave_get_session_client(sesskey, sessIV);
            if (eres_getsession != 1) { return null; }
            Array.Resize(ref sesskey, Array.FindLastIndex(sesskey, b => b != 0) + 1);
            Array.Resize(ref sessIV, Array.FindLastIndex(sessIV, b => b != 0) + 1);
            TestPrint("Client session [{0}]", string.Join(", ", sesskey));
            TestPrint("Client iv [{0}]", string.Join(", ", sessIV));


            // The client could then in the end decrypt back the result
            //**** START CLIENT CODE ****//
            byte[] sesskeyplain = rsa_client.Decrypt(sesskey, RSAEncryptionPadding.OaepSHA256);
            byte[] sessIVplain = rsa_client.Decrypt(sessIV, RSAEncryptionPadding.OaepSHA256);
            TestPrint("Client session decrypted at client [{0}]", string.Join(", ", sesskeyplain));
            TestPrint("Client iv decrypted at client [{0}]", string.Join(", ", sessIVplain));

            Aes aes_client2 = Aes.Create();
            aes_client2.Mode = CipherMode.CBC;
            aes_client2.Key = sesskeyplain;
            aes_client2.IV = sessIVplain;

            byte[] prebackwardplain = aes_client2.DecryptCbc(result_prebackward, aes_client2.IV);
            TestPrint("Decrypted bytes at client: [{0}]", string.Join(", ", prebackwardplain));
            TestPrint("Try decoding the decrypted string: " + Encoding.UTF8.GetString(prebackwardplain));
            //**** END CLIENT CODE ****//

            return prebackwardplain;

        }

    }
}
