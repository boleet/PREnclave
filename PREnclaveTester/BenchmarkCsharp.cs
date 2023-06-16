using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Reports;
using System.Security.Cryptography;
using System.Text;

namespace PREnclaveTester
{
    [MarkdownExporter, AsciiDocExporter, HtmlExporter, CsvExporter, RPlotExporter]
    [Config(typeof(Config))]
    public class BenchmarkCsharp
    {

        private class Config : ManualConfig
        {
            public Config()
            {
                AddColumn(
                    StatisticColumn.P0,
                    StatisticColumn.P90,
                    StatisticColumn.P95,
                    StatisticColumn.P100);

                this.WithSummaryStyle(SummaryStyle.Default.WithTimeUnit(Perfolizer.Horology.TimeUnit.Millisecond));
            }
        }


        /**
         * Benchmarks similar to the BenchmarkTestsTEE, but then implemented in C#.
         * This allows for comparison of the same Proxy Re-Encryption functionality
         * beeing executed in a Trusted Execution Environment vs in untrusted C#.
         */


        /**************** Benchmark enclave creation ****************/
        /*
         * Create a new enclave
         */


        [Benchmark]
        public void Bench_CreateEnclaveManager()
        {
            // Nothing to do :)
        }



        /**************** Benchmark setting enclave private key ****************/
        /*
         * Given the private key as bytes, initialize a new proxy RSA object
         */


        string privatekey;
        [IterationSetup(Targets = new[] { nameof(Bench_SetPrivateKeyProxy) })]
        public void Setup_SetPrivateKeyProxy()
        {
            RSA keygen = RSA.Create();
            privatekey = keygen.ExportRSAPrivateKeyPem();
        }

        [Benchmark]
        public void Bench_SetPrivateKeyProxy()
        {
            RSA rsa_api = RSA.Create();
            rsa_api.ImportFromPem(privatekey);
        }


        /**************** Benchmark getting enclave public key ****************/
        /*
         * Given an initialized proxy RSA object, retrieve the public key as bytes
         */

        [IterationSetup(Targets = new[] { nameof(Bench_GetPublicKeyProxy) })]
        public void Setup_GetPublicKeyProxy()
        {
            SetPrivateProxyKey();
        }


        [Benchmark]
        public void Bench_GetPublicKeyProxy()
        {
            byte[] a = rsa_api.ExportPkcs8PrivateKey();

        }


        /**************** Benchmark creating client session ****************/
        /*
         * Given the encrypted AES session key and IV, and client public key (all as bytes), create both a forward and backward AES object 
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_CreateSessionClient) })]
        public void SetupG_CreateSessionClient()
        {
            SetPrivateProxyKey();
            GetProxyPublicKey();

        }

        byte[] key_enc, iv_enc, pk_client;
        [IterationSetup(Targets = new[] { nameof(Bench_CreateSessionClient) })]
        public void Setup_CreateSessionClient()
        {
            aes_client = Aes.Create();
            aes_client.Mode = CipherMode.CBC;

            rsa_client = RSA.Create();

            key_enc = rsa_api.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256); // Encrypt newly generated 
            iv_enc = rsa_api.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            pk_client = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
        }

        [Benchmark]
        public void Bench_CreateSessionClient()
        {
            // Decrypt the received values and create AES object such that we can decrypt values received from client
            byte[] key = rsa_api.Decrypt(key_enc, RSAEncryptionPadding.OaepSHA256);
            byte[] iv = rsa_api.Decrypt(iv_enc, RSAEncryptionPadding.OaepSHA256);
            Aes aes_proxy = Aes.Create();
            aes_proxy.Mode = CipherMode.CBC;
            aes_proxy.Key = key;
            aes_proxy.IV = iv;

            Aes aes_proxy_backward = Aes.Create();

            RSA rsa_client_public = RSA.Create();
            rsa_client_public.ImportFromPem(Encoding.UTF8.GetString(pk_client).ToCharArray());
        }




        /**************** Benchmark getting client session ****************/
        /*
         * Given an initialized backward AES object, retrieve the encrypted session key and IV (as bytes)
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_GetSessionClient) })]
        public void SetupG_GetSessionClient()
        {
            SetPrivateProxyKey();
            GetProxyPublicKey();
        }

        [IterationSetup(Targets = new[] { nameof(Bench_GetSessionClient) })]
        public void Setup_GetSessionClient()
        {
            SetSession();
        }

        [Benchmark]
        public void Bench_GetSessionClient()
        {
            byte[] result_session_client_key = rsa_client_public.Encrypt(aes_proxy_backward.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] result_session_client_iv = rsa_client_public.Encrypt(aes_proxy_backward.IV, RSAEncryptionPadding.OaepSHA256);
        }



        /**************** Benchmark PREForward ****************/
        /*
         * Given an AES key (as bytes), initialize an AES object
         */

        Aes aes_proxy_db_bench;
        [GlobalSetup(Targets = new[] { nameof(Bench_SetDBKey) })]
        public void SetupG_SetDBKey()
        {
            aes_proxy_db_bench = Aes.Create();
        }
        [Benchmark]
        public void Bench_SetDBKey()
        {
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            aes_proxy_db_bench = Aes.Create();
            aes_proxy_db_bench.Key = fakekey;
        }

        /**************** Benchmark PREForward ****************/
        /*
         * Given an initialized session (with client and with database) and incoming data (as bytes), decrypt incoming data and encrypt towards the database.
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_PREForward) })]
        public void SetupG_PREForward()
        {
            SetPrivateProxyKey();
            SetDBKey();
            GetProxyPublicKey();
            SetSession();
        }


        List<byte[]> PREForwardInputs = new List<byte[]>();
        const int max_input_amount_forward = 1000;
        [IterationSetup(Targets = new[] { nameof(Bench_PREForward) })]
        public void Setup_PREForward()
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const int input_size = 20;
            for (int i = 0; i < max_input_amount_forward; i++)
            {
                string val = new string(Enumerable.Repeat(chars, input_size).Select(s => s[random.Next(s.Length)]).ToArray());
                PREForwardInputs.Add(PREForwardGenerateInput(val));
            }
        }


        [Benchmark]
        [Arguments(1)]
        [Arguments(10)] // Note: max_input_amount_forward above Setup_PREForward should be the max specified here
        [Arguments(100)]
        [Arguments(1000)]
        public void Bench_PREForward(int pre_amount)
        {
            Random random = new Random();
            for (int i = 0; i < pre_amount; i++)
            {
                byte[] plain = aes_proxy.DecryptCbc(PREForwardInputs[i], aes_proxy.IV);

                byte[] iv = new byte[16];
                random.NextBytes(iv);

                byte[] enc = aes_database.EncryptCbc(plain, iv); // Not actually CBC, but good enough for now

                byte[] result = new byte[1 + 16 + 32 + enc.Length];

                result[0] = 1; // version byte

                Buffer.BlockCopy(iv, 0, result, 1, 16); // IV

                // Calculate mac (dummy)
                byte[] mackey = new byte[32];
                using (HMACSHA256 hmac = new HMACSHA256())
                {
                    byte[] dummyinput = Encoding.UTF8.GetBytes("dummykey salt"); // Do not calculate actual key for simplicity, but computationally it should be the same

                    mackey = hmac.ComputeHash(dummyinput);

                }

                byte[] mac = new byte[32];
                using (HMACSHA256 hmac = new HMACSHA256(mackey))
                {
                    byte[] dummyinput = Encoding.UTF8.GetBytes("test");

                    mac = hmac.ComputeHash(dummyinput);

                }
                Buffer.BlockCopy(mac, 0, result, 1 + 16, 32);

                Buffer.BlockCopy(enc, 0, result, 1 + 16 + 32, enc.Length); // ciphertext
            }
        }



        /**************** Benchmark PREBackward ****************/
        /*
        * Given an initialized session (with client and with database) and incoming data (as bytes), decrypt incoming data and encrypt towards the client.
        */

        [GlobalSetup(Targets = new[] { nameof(Bench_PREBackward) })]
        public void SetupG_PREBackward()
        {
            CreateEnclaveManager();
            SetPrivateProxyKey();
            SetDBKey();
            GetProxyPublicKey();
            SetSession();
            GetSessionClient();
        }

        List<byte[]> PREBackwardInputs = new List<byte[]>();
        const int max_input_amount_backward = 1000;
        [IterationSetup(Targets = new[] { nameof(Bench_PREBackward) })]
        public void Setup_PREBackward()
        {
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const int input_size = 20;
            for (int i = 0; i < max_input_amount_backward; i++)
            {
                string val = new string(Enumerable.Repeat(chars, input_size).Select(s => s[random.Next(s.Length)]).ToArray());
                PREBackwardInputs.Add(PREForward(PREForwardGenerateInput(val)));
            }
        }

        [Benchmark]
        [Arguments(1)]
        [Arguments(10)] // Note: max_input_amount_backward above Setup_PREBackward should be the max specified here
        [Arguments(100)]
        [Arguments(1000)]
        public void Bench_PREBackward(int pre_amount)
        {
            for (int i = 0; i < pre_amount; i++)
            {
                byte[] currentinput = PREBackwardInputs[i];

                byte[] iv = new byte[16];
                Buffer.BlockCopy(currentinput, 1, iv, 0, 16);

                int ciphertext_len = currentinput.Length - (1 + 16 + 32);
                byte[] ciphertext = new byte[ciphertext_len];
                Buffer.BlockCopy(currentinput, 1 + 16 + 32, ciphertext, 0, ciphertext_len);

                // Validate MAC (dummy)
                byte[] mackey = new byte[32];
                using (HMACSHA256 hmac = new HMACSHA256())
                {
                    byte[] dummyinput = Encoding.UTF8.GetBytes("dummykey salt"); // Do not calculate actual key for simplicity, but computationally it should be the same

                    mackey = hmac.ComputeHash(dummyinput);

                }

                byte[] mac = new byte[32];
                using (HMACSHA256 hmac = new HMACSHA256(mackey))
                {
                    byte[] dummyinput = ciphertext;

                    mac = hmac.ComputeHash(dummyinput);

                }


                byte[] plain = aes_database.DecryptCbc(ciphertext, iv);
                byte[] res = aes_proxy_backward.EncryptCbc(plain, aes_proxy_backward.IV);
            }
        }



        /**************** Benchmark typical full run of the enclave ****************/

        // We try to put as much client code as possible in the setup, such that
        // the benchmark represent all proxy effort to initialize an enclave and perform
        // PREForward and PREBackward

        byte[] rsa_api_secretkey_full;
        byte[] key_enc_full, iv_enc_full, pk_client_full;
        Aes aes_client_forward_full;
        [GlobalSetup(Targets = new[] { nameof(Bench_FullRun) })]
        public void SetupG_FullRun()
        {
            RSA rsa_api_full = RSA.Create(); // Actually this is performed on the server, but in the end we want to eliminate this at all; therefore we put it outside of the benchmark
            rsa_api_secretkey_full = rsa_api_full.ExportPkcs8PrivateKey();

            aes_client_forward_full = Aes.Create();
            aes_client_forward_full.Mode = CipherMode.CBC;
            aes_client_forward_full.GenerateKey();
            key_enc_full = rsa_api_full.Encrypt(aes_client_forward_full.Key, RSAEncryptionPadding.OaepSHA256);
            iv_enc_full = rsa_api_full.Encrypt(aes_client_forward_full.IV, RSAEncryptionPadding.OaepSHA256);

            RSA rsa_client_full = RSA.Create();
            pk_client_full = Encoding.UTF8.GetBytes(rsa_client_full.ExportSubjectPublicKeyInfoPem());
        }





        //string rsa_api_secretkey_full;

        List<byte[]> PREInputs_full = new List<byte[]>();
        [IterationSetup(Targets = new[] { nameof(Bench_FullRun) })]
        public void Setup_FullRun()
        {
            PREInputs_full.Clear();

            int max_input_amount_full = 1000;

            // Generate random inputs
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const int input_size = 20;
            for (int i = 0; i < max_input_amount_full; i++)
            {
                string val = new string(Enumerable.Repeat(chars, input_size).Select(s => s[random.Next(s.Length)]).ToArray());
                PREInputs_full.Add(aes_client_forward_full.EncryptCbc(Encoding.UTF8.GetBytes(val), aes_client_forward_full.IV));
            }
        }


        [Benchmark]
        [Arguments(1)]
        [Arguments(10)]
        [Arguments(100)]
        [Arguments(1000)]
        public void Bench_FullRun(int pre_amount)
        {
            // Create proxy RSA and set private key
            RSA rsa_api_full = RSA.Create();
            //rsa_api_full.ImportFromPem(rsa_api_secretkey_full);
            rsa_api_full.ImportPkcs8PrivateKey(rsa_api_secretkey_full, out _);


            // Set client forward session
            byte[] key = rsa_api_full.Decrypt(key_enc_full, RSAEncryptionPadding.OaepSHA256);
            byte[] iv = rsa_api_full.Decrypt(iv_enc_full, RSAEncryptionPadding.OaepSHA256);
            Aes aes_api_forward_full = Aes.Create();
            aes_api_forward_full.Mode = CipherMode.CBC;
            aes_api_forward_full.Key = key;
            aes_api_forward_full.IV = iv;


            // Get client backward session
            RSA rsa_client_public_full = RSA.Create();
            rsa_client_public_full.ImportFromPem(Encoding.UTF8.GetString(pk_client_full).ToCharArray());
            Aes aes_api_backward_full = Aes.Create();
            byte[] result_session_client_key = rsa_client_public_full.Encrypt(aes_api_backward_full.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] result_session_client_iv = rsa_client_public_full.Encrypt(aes_api_backward_full.IV, RSAEncryptionPadding.OaepSHA256);

            // Set database private key
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            Aes aes_database_full = Aes.Create();
            aes_database_full.Key = fakekey;

            // PREForward on random data
            List<byte[]> PREresults_full = new List<byte[]>();

            Random random = new Random();
            for (int i = 0; i < pre_amount; i++)
            {
                // Decrypt input
                byte[] plain_full = aes_api_forward_full.DecryptCbc(PREInputs_full[i], aes_api_forward_full.IV);

                // New random IV
                byte[] iv_full = new byte[16];
                random.NextBytes(iv_full);

                // Encrypt plain data towards database
                aes_database_full.IV = iv_full; // is this necessary?
                byte[] enc_full = aes_database_full.EncryptCbc(plain_full, iv_full);

                // Create buffer and set version byte, IV, MAC and ciphertext
                byte[] result_full = new byte[1 + 16 + 32 + enc_full.Length];

                result_full[0] = 1; // version byte
                Buffer.BlockCopy(iv_full, 0, result_full, 1, 16); // IV

                // Calculate key for mac (dummy)
                byte[] mackey_full = new byte[32];
                using (HMACSHA256 hmac_full = new HMACSHA256())
                {
                    byte[] dummyinput_full = Encoding.UTF8.GetBytes("dummykey salt"); // Do not calculate actual key for simplicity, but computationally it should be the same

                    mackey_full = hmac_full.ComputeHash(dummyinput_full);

                }

                // Calculate MAC on data using the mackey
                byte[] mac_full = new byte[32];
                using (HMACSHA256 hmac_full = new HMACSHA256(mackey_full))
                {
                    byte[] dummyinput_full = Encoding.UTF8.GetBytes("another dummyinput");

                    mac_full = hmac_full.ComputeHash(dummyinput_full);

                }
                Buffer.BlockCopy(mac_full, 0, result_full, 1 + 16, 32); // MAC

                Buffer.BlockCopy(enc_full, 0, result_full, 1 + 16 + 32, enc_full.Length); // ciphertext

                PREresults_full.Add(result_full);
            }

            // PREBackward

            for (int i = 0; i < pre_amount; i++)
            {
                byte[] currentinput_full = PREresults_full[i];

                // Extract IV
                byte[] iv_full = new byte[16];
                Buffer.BlockCopy(currentinput_full, 1, iv_full, 0, 16);

                // Extract ciphertext
                int ciphertext_len_full = currentinput_full.Length - (1 + 16 + 32);
                byte[] ciphertext_full = new byte[ciphertext_len_full];
                Buffer.BlockCopy(currentinput_full, 1 + 16 + 32, ciphertext_full, 0, ciphertext_len_full);

                // Validate MAC (dummy)
                byte[] mackey = new byte[32];
                using (HMACSHA256 hmac = new HMACSHA256())
                {
                    byte[] dummyinput = Encoding.UTF8.GetBytes("dummykey salt"); // Do not calculate actual key for simplicity, but computationally it should be the same

                    mackey = hmac.ComputeHash(dummyinput);

                }

                byte[] mac = new byte[32];
                using (HMACSHA256 hmac = new HMACSHA256(mackey))
                {
                    byte[] dummyinput = ciphertext_full;

                    mac = hmac.ComputeHash(dummyinput);

                }


                // Decrypt data from databasse
                byte[] plain_full = aes_database_full.DecryptCbc(ciphertext_full, iv_full);

                // Encrypt towards client backward
                byte[] res_full = aes_api_backward_full.EncryptCbc(plain_full, aes_api_backward_full.IV);
            }
        }








        /**************** Functions & utils ****************/




        public void CreateEnclaveManager()
        {
            // Nothing to do :)
        }

        RSA rsa_api;
        public void SetPrivateProxyKey()
        {
            rsa_api = RSA.Create();
        }

        public void GetProxyPublicKey()
        {
            rsa_api.ExportPkcs8PrivateKey();
        }


        Aes aes_client;
        RSA rsa_client;
        RSA rsa_client_public;
        Aes aes_proxy; // Use to decrypt incoming encrypted requests
        Aes aes_proxy_backward; // Use to encrypt backward outgoing data
        byte[] client_publickey;
        // Requires GetProxyPublicKey() and dependencies
        public void SetSession()
        {
            //**** START CLIENT CODE ****//
            aes_client = Aes.Create();
            aes_client.Mode = CipherMode.CBC;

            rsa_client = RSA.Create();
            // Since we do not focus on the client code, just use rsa_api object; in real, it would only have public key set
            byte[] key_enc = rsa_api.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256); // Encrypt newly generated 
            byte[] iv_enc = rsa_api.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            client_publickey = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            //**** END CLIENT CODE ****//


            // Decrypt the received values and create AES object such that we can decrypt values received from client
            byte[] key = rsa_api.Decrypt(key_enc, RSAEncryptionPadding.OaepSHA256);
            byte[] iv = rsa_api.Decrypt(iv_enc, RSAEncryptionPadding.OaepSHA256);
            aes_proxy = Aes.Create();
            aes_proxy.Mode = CipherMode.CBC;
            aes_proxy.Key = key;
            aes_proxy.IV = iv;

            // Public RSA of client to encrypt towards
            rsa_client_public = RSA.Create();
            rsa_client_public.ImportFromPem(Encoding.UTF8.GetString(client_publickey).ToCharArray());

            // New backward session
            aes_proxy_backward = Aes.Create();
        }



        public void GetSessionClient()
        {
            byte[] result_session_client_key = rsa_client_public.Encrypt(aes_proxy_backward.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] result_session_client_iv = rsa_client_public.Encrypt(aes_proxy_backward.IV, RSAEncryptionPadding.OaepSHA256);

        }


        Aes aes_database; // Use to encrypt/decrypt database values to
        // Requires CreateEnclaveManager() only
        public void SetDBKey()
        {
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            aes_database = Aes.Create();
            aes_database.Key = fakekey;
        }


        // Requires SetSession() and dependencies
        public byte[] PREForwardGenerateInput(string data)
        {
            byte[] raw_input = Encoding.UTF8.GetBytes(data);
            byte[] data_preforward = aes_client.EncryptCbc(raw_input, aes_client.IV);

            return data_preforward;
        }

        // Requires PREForwardGenerateInput() and dependencies
        public byte[] PREForward(byte[] data_preforward)
        {
            Random random = new Random();
            byte[] plain = aes_proxy.DecryptCbc(data_preforward, aes_proxy.IV);

            byte[] iv = new byte[16];
            random.NextBytes(iv);

            byte[] enc = aes_database.EncryptCbc(plain, iv); // Not actually CBC, but good enough for now

            byte[] result = new byte[1 + 16 + 32 + enc.Length];

            result[0] = 1; // version byte

            Buffer.BlockCopy(iv, 0, result, 1, 16); // IV

            byte[] mackey = new byte[32];
            using (HMACSHA256 hmac = new HMACSHA256())
            {
                byte[] dummyinput = Encoding.UTF8.GetBytes("dummykey salt"); // Do not calculate actual key for simplicity, but computationally it should be the same
                mackey = hmac.ComputeHash(dummyinput);

            }

            byte[] mac = new byte[32];
            using (HMACSHA256 hmac = new HMACSHA256(mackey))
            {
                byte[] dummyinput = enc; // Actually the hash is not computed on only this, but computationally it should be similar
                mac = hmac.ComputeHash(dummyinput);

            }
            Buffer.BlockCopy(mac, 0, result, 1 + 16, 32);

            Buffer.BlockCopy(enc, 0, result, 1 + 16 + 32, enc.Length); // ciphertext

            return result;
        }

        // Requires PREForward() and dependencies
        public byte[] PREBackward(byte[] data_prebackward)
        {

            byte[] currentinput = data_prebackward;

            byte[] iv = new byte[16];
            Buffer.BlockCopy(currentinput, 1, iv, 0, 16);

            int ciphertext_len = currentinput.Length - (1 + 16 + 32);
            byte[] ciphertext = new byte[ciphertext_len];
            Buffer.BlockCopy(currentinput, 1 + 16 + 32, ciphertext, 0, ciphertext_len);


            byte[] plain = aes_database.DecryptCbc(ciphertext, iv);
            byte[] res = aes_proxy_backward.EncryptCbc(plain, aes_proxy_backward.IV);

            return res;
        }


        public byte[] PREBackwardDecryptOutput(byte[] result_prebackward)
        {
            // TODO
            return null;


            // Check the session (encrypted towards public key of the client)
            byte[] sesskey = new byte[256];
            byte[] sessIV = new byte[256];

            //if (eres_getsession != 1) { return null; }
            Array.Resize(ref sesskey, Array.FindLastIndex(sesskey, b => b != 0) + 1);
            Array.Resize(ref sessIV, Array.FindLastIndex(sessIV, b => b != 0) + 1);


            // The client could then in the end decrypt back the result

            //**** START CLIENT CODE ****//
            byte[] sesskeyplain = rsa_client.Decrypt(sesskey, RSAEncryptionPadding.OaepSHA256);
            byte[] sessIVplain = rsa_client.Decrypt(sessIV, RSAEncryptionPadding.OaepSHA256);

            Aes aes_client2 = Aes.Create();
            aes_client2.Mode = CipherMode.CBC;
            aes_client2.Key = sesskeyplain;
            aes_client2.IV = sessIVplain;

            byte[] prebackwardplain = aes_client2.DecryptCbc(result_prebackward, aes_client2.IV);
            //**** END CLIENT CODE ****//

            return prebackwardplain;
        }



    }
}
