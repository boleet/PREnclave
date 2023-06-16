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
    public class BenchmarkTEE
    {


        /**
         * Benchmarks for the PREnclaveSGX code.
         * The benchmark only contain the calls to the enclave. The utility functions
         * at the bottom also include surrounding C# code. This is only used for setting
         * up the benchmarks and not included in the benchmarks themselves.
         */

        public void GlobalSetup()
        {

        }

        int Bench_SetPrivateKeyProxy_error = 0;
        int Bench_GetPublicKeyProxy_error = 0;
        int Bench_CreateSessionClient_error = 0;
        int Bench_GetSessionClient_error = 0;
        int Bench_PREForward_error = 0;
        int Bench_PREBackward_error = 0;
        int Bench_FullRun_error = 0;

        [GlobalCleanup]
        public void GlobalCleanup()
        {
            Console.WriteLine("Errors Bench_SetPrivateKeyProxy_error: " + Bench_SetPrivateKeyProxy_error);
            Console.WriteLine("Errors Bench_GetPublicKeyProxy_error: " + Bench_GetPublicKeyProxy_error);
            Console.WriteLine("Errors Bench_CreateSessionClient_error: " + Bench_CreateSessionClient_error);
            Console.WriteLine("Errors Bench_GetSessionClient_error: " + Bench_GetSessionClient_error);
            Console.WriteLine("Errors Bench_PREForward_error: " + Bench_PREForward_error);
            Console.WriteLine("Errors Bench_PREBackward_error: " + Bench_PREBackward_error);
            Console.WriteLine("Errors Bench_FullRun_error: " + Bench_FullRun_error);
        }

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


        /**************** Benchmark enclave creation ****************/
        /*
         * Create a new enclave
         */

        PREnclaveLinkManaged bench_enclave;
        [Benchmark]
        public void Bench_CreateEnclaveManager()
        {
            bench_enclave = new PREnclaveLinkManaged();
        }

        [IterationCleanup(Target = nameof(Bench_CreateEnclaveManager))]
        public void Cleanup_CreateEnclaveManager()
        {
            bench_enclave.Dispose();
        }



        /**************** Benchmark setting enclave private key ****************/
        /*
         * Given the private key as bytes, initialize a new proxy RSA object
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_SetPrivateKeyProxy) })]
        public void SetupG_SetPrivateKeyProxy()
        {
            CreateEnclaveManager();
        }

        [GlobalCleanup(Targets = new[] { nameof(Bench_SetPrivateKeyProxy) })]
        public void CleanupG_SetPrivateKeyProxy()
        {
            DestroyEnclaveManager();
        }

        byte[] privatekey;
        [IterationSetup(Targets = new[] { nameof(Bench_SetPrivateKeyProxy) })]
        public void Setup_SetPrivateKeyProxy()
        {
            RSA keygen = RSA.Create();
            privatekey = keygen.ExportPkcs8PrivateKey();
        }

        [Benchmark]
        public void Bench_SetPrivateKeyProxy()
        {
            int eres_setprivatekeyproxy = enclave.enclave_set_private_key_proxy_insecure(privatekey);
            if (eres_setprivatekeyproxy != 1)
            {
                Bench_SetPrivateKeyProxy_error += 1;
            }
        }


        /**************** Benchmark getting enclave public key ****************/
        /*
         * Given an initialized proxy RSA object, retrieve the public key as bytes
         */


        [GlobalSetup(Targets = new[] { nameof(Bench_GetPublicKeyProxy) })]
        public void SetupG_GetPublicKeyProxy()
        {
            CreateEnclaveManager();
        }

        [GlobalCleanup(Targets = new[] { nameof(Bench_GetPublicKeyProxy) })]
        public void CleanupG_GetPublicKeyProxy()
        {
            DestroyEnclaveManager();
        }

        [IterationSetup(Targets = new[] { nameof(Bench_GetPublicKeyProxy) })]
        public void Setup_GetPublicKeyProxy()
        {
            SetPrivateProxyKey();
        }


        [Benchmark]
        public void Bench_GetPublicKeyProxy()
        {
            byte[] result_proxy_publickey = new byte[1024];
            int eres_getpublickeyproxy = enclave.enclave_get_public_key_proxy(result_proxy_publickey);
            if (eres_getpublickeyproxy != 1)
            {
                Bench_GetPublicKeyProxy_error += 1;
            }
            Array.Resize(ref result_proxy_publickey, Array.FindLastIndex(result_proxy_publickey, b => b != 0) + 1);

        }


        /**************** Benchmark creating client session ****************/
        /*
         * Given the encrypted AES session key and IV, and client public key (all as bytes), create both a forward and backward AES object 
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_CreateSessionClient) })]
        public void SetupG_CreateSessionClient()
        {
            CreateEnclaveManager();
            SetPrivateProxyKey();
            GetProxyPublicKey();

        }

        [GlobalCleanup(Targets = new[] { nameof(Bench_CreateSessionClient) })]
        public void CleanupG_CreateSessionClient()
        {
            DestroyEnclaveManager();
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
            int eres_createsession = enclave.enclave_session(key_enc, iv_enc, pk_client);
            if (eres_createsession != 1)
            {
                Bench_CreateSessionClient_error += 1;
            }
        }

        /**************** Benchmark getting client session ****************/
        /*
         * Given an initialized backward AES object, retrieve the encrypted session key and IV (as bytes)
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_GetSessionClient) })]
        public void SetupG_GetSessionClient()
        {
            CreateEnclaveManager();
            SetPrivateProxyKey();
            GetProxyPublicKey();
        }

        [GlobalCleanup(Targets = new[] { nameof(Bench_GetSessionClient) })]
        public void CleanupG_GetSessionClient()
        {
            DestroyEnclaveManager();
        }

        [IterationSetup(Targets = new[] { nameof(Bench_GetSessionClient) })]
        public void Setup_GetSessionClient()
        {
            SetSession();
        }

        [Benchmark]
        public void Bench_GetSessionClient()
        {
            byte[] result_session_client_key = new byte[1024];
            byte[] result_session_client_iv = new byte[1024];
            int eres_getsessionclient = enclave.enclave_get_session_client(result_session_client_key, result_session_client_iv);
            if (eres_getsessionclient != 1)
            {
                Bench_GetSessionClient_error += 1;
            }
            Array.Resize(ref result_session_client_key, Array.FindLastIndex(result_session_client_key, b => b != 0) + 1);
            Array.Resize(ref result_session_client_iv, Array.FindLastIndex(result_session_client_iv, b => b != 0) + 1);
        }


        /**************** Benchmark PREForward ****************/
        /*
         * Given an AES key (as bytes), initialize an AES object
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_SetDBKey) })]
        public void SetupG_SetDBKey()
        {
            CreateEnclaveManager();
        }
        [Benchmark]
        public void Bench_SetDBKey()
        {
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            int eres_setdbkey = enclave.enclave_set_key_db_insecure(fakekey);
        }

        /**************** Benchmark PREForward ****************/
        /*
         * Given an initialized session (with client and with database) and incoming data (as bytes), decrypt incoming data and encrypt towards the database.
         */

        [GlobalSetup(Targets = new[] { nameof(Bench_PREForward) })]
        public void SetupG_PREForward()
        {
            CreateEnclaveManager();
            SetPrivateProxyKey();
            SetDBKey();
            GetProxyPublicKey();
            SetSession();
        }

        [GlobalCleanup(Targets = new[] { nameof(Bench_PREForward) })]
        public void CleanupG_PREForward()
        {
            DestroyEnclaveManager();
        }


        List<byte[]> PREForwardInputs = new List<byte[]>();
        const int max_input_amount_forward = 1000;
        [IterationSetup(Targets = new[] { nameof(Bench_PREForward) })]
        public void Setup_PREForward()
        {
            PREForwardInputs.Clear();
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
            for (int i = 0; i < pre_amount; i++)
            {
                byte[] result_preforward = new byte[1 + 32 + 16 + PREForwardInputs[i].Length]; // length = versionbyte (1) + MAC (32) + IV (16) + encrypted data size
                int eres_prenclaveforward = enclave.enclave_PREForward(PREForwardInputs[i], result_preforward);
                if (eres_prenclaveforward != 1)
                {
                    Bench_PREForward_error += 1;
                }
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
        }

        [GlobalCleanup(Targets = new[] { nameof(Bench_PREBackward) })]
        public void CleanupG_PREBackward()
        {
            DestroyEnclaveManager();
        }

        List<byte[]> PREBackwardInputs = new List<byte[]>();
        const int max_input_amount_backward = 1000;
        [IterationSetup(Targets = new[] { nameof(Bench_PREBackward) })]
        public void Setup_PREBackward()
        {
            PREBackwardInputs.Clear();
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
                byte[] result_prebackward = new byte[PREBackwardInputs[i].Length];
                int eres_prenclavebackward = enclave.enclave_PREBackward(PREBackwardInputs[i], result_prebackward);
                if (eres_prenclavebackward != 1)
                {
                    Bench_PREBackward_error += 1;
                }
                Array.Resize(ref result_prebackward, Array.FindLastIndex(result_prebackward, b => b != 0) + 1);
            }
        }



        /**************** Benchmark typical full run of the enclave ****************/

        // We try to put as much client code as possible in the setup, such that
        // the benchmark represent all proxy effort to initialize an enclave and perform
        // PREForward and PREBackward

        [GlobalSetup(Targets = new[] { nameof(Bench_FullRun) })]
        public void SetupG_FullRun()
        {

        }



        List<byte[]> PREInputs = new List<byte[]>();
        const int max_input_amount_full = 1000;
        byte[] rsa_api_secretkey_full;
        byte[] key_enc_full, iv_enc_full, pk_client_full;
        [IterationSetup(Targets = new[] { nameof(Bench_FullRun) })]
        public void Setup_FullRun()
        {
            PREInputs.Clear(); // Remove inputs from previous iteration

            RSA rsa_client_full = RSA.Create();


            RSA rsa_api_secretkeygen_full = RSA.Create(); // Actually this is performed on the server, but in the end we want to eliminate this at all; therefore we put it outside of the benchmark
            rsa_api_secretkey_full = rsa_api_secretkeygen_full.ExportPkcs8PrivateKey();

            Aes aes_client_full = Aes.Create();
            aes_client_full.Mode = CipherMode.CBC;
            key_enc_full = rsa_api_secretkeygen_full.Encrypt(aes_client_full.Key, RSAEncryptionPadding.OaepSHA256);
            iv_enc_full = rsa_api_secretkeygen_full.Encrypt(aes_client_full.IV, RSAEncryptionPadding.OaepSHA256);
            pk_client_full = Encoding.UTF8.GetBytes(rsa_client_full.ExportSubjectPublicKeyInfoPem());


            // Generate random inputs
            Random random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            const int input_size = 20;
            for (int i = 0; i < max_input_amount_full; i++)
            {
                string val = new string(Enumerable.Repeat(chars, input_size).Select(s => s[random.Next(s.Length)]).ToArray());
                PREInputs.Add(aes_client_full.EncryptCbc(Encoding.UTF8.GetBytes(val), aes_client_full.IV));
            }
        }


        [Benchmark]
        [Arguments(1)]
        [Arguments(10)]
        [Arguments(100)]
        [Arguments(1000)]
        public void Bench_FullRun(int pre_amount)
        {
            // Create Enclave
            PREnclaveLinkManaged enclave_full = new PREnclaveLinkManaged();

            // Set RSA private key
            int eres_setprivatekeyproxy = enclave_full.enclave_set_private_key_proxy_insecure(rsa_api_secretkey_full);
            if (eres_setprivatekeyproxy != 1)
            {
                Bench_FullRun_error += 1;
                Console.WriteLine("Error: setting private key proxy");
            }

            // Set client session
            int eres_createsession = enclave_full.enclave_session(key_enc_full, iv_enc_full, pk_client_full);
            if (eres_createsession != 1)
            {
                Bench_FullRun_error += 1;
                Console.WriteLine("Error: setting enclave session");
            }

            // Set database key
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            int eres_setdbkey = enclave_full.enclave_set_key_db_insecure(fakekey);
            if (eres_setdbkey != 1)
            {
                Bench_FullRun_error += 1;
                Console.WriteLine("Error: setting db key");
            }

            List<byte[]> PREresults = new List<byte[]>();

            for (int i = 0; i < pre_amount; i++)
            {
                byte[] data_preforward = PREInputs[i];
                byte[] result_preforward = new byte[1 + 32 + 16 + data_preforward.Length]; // length = versionbyte (1) + MAC (32) + IV (16) + encrypted data size
                int eres_prenclaveforward = enclave_full.enclave_PREForward(data_preforward, result_preforward);
                if (eres_prenclaveforward != 1)
                {
                    Bench_FullRun_error += 1;
                    Console.WriteLine("Error: preforward " + eres_prenclaveforward);
                }
                PREresults.Add(result_preforward);
            }
            for (int i = 0; i < pre_amount; i++)
            {
                byte[] data_prebackward = PREresults[i];
                byte[] result_prebackward = new byte[data_prebackward.Length];
                int eres_prenclavebackward = enclave_full.enclave_PREBackward(data_prebackward, result_prebackward);
                if (eres_prenclavebackward != 1)
                {
                    Bench_FullRun_error += 1;
                    Console.WriteLine("Error: prebackward " + eres_prenclavebackward);
                }
                Array.Resize(ref result_prebackward, Array.FindLastIndex(result_prebackward, b => b != 0) + 1);
            }


            enclave_full.Dispose();
        }















        /**************** Functions & utils ****************/

        PREnclaveLinkManaged enclave;
        public void CreateEnclaveManager()
        {
            enclave = new PREnclaveLinkManaged();
        }

        public void DestroyEnclaveManager()
        {
            enclave.Dispose();
        }

        // Requires CreateEnclaveManager()
        public void SetPrivateProxyKey()
        {
            RSA rsa_api_secretkeygen = RSA.Create();
            byte[] rsa_api_secretkey = rsa_api_secretkeygen.ExportPkcs8PrivateKey();
            int eres_setprivatekeyproxy = enclave.enclave_set_private_key_proxy_insecure(rsa_api_secretkey);
        }

        RSA rsa_api;
        // Requires SetPrivateProxyKey() and dependencies
        public void GetProxyPublicKey()
        {
            rsa_api = RSA.Create();
            byte[] result_proxy_publickey = new byte[1024];
            int eres_getpublickeyproxy = enclave.enclave_get_public_key_proxy(result_proxy_publickey);
            //if (eres_getpublickeyproxy != 1) { return false; }
            Array.Resize(ref result_proxy_publickey, Array.FindLastIndex(result_proxy_publickey, b => b != 0) + 1);

            // Set the public key of our rsa_api object, such that we can encrypt messages toward the proxy
            System.String result_proxy_publickey_string = Encoding.UTF8.GetString(result_proxy_publickey).Replace("-----BEGIN PUBLIC KEY-----\n", "").Replace("-----END PUBLIC KEY-----\n", "").ReplaceLineEndings("");
            byte[] reult_proxy_publickey_bytes = System.Convert.FromBase64String(result_proxy_publickey_string);
            rsa_api.ImportSubjectPublicKeyInfo(reult_proxy_publickey_bytes, out _);
        }


        Aes aes_client;
        RSA rsa_client;
        // Requires GetProxyPublicKey() and dependencies
        public void SetSession()
        {
            //**** START CLIENT CODE ****//
            aes_client = Aes.Create();
            aes_client.Mode = CipherMode.CBC;

            rsa_client = RSA.Create();

            byte[] key_enc = rsa_api.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256); // Encrypt newly generated 
            byte[] iv_enc = rsa_api.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] pk_client = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            //**** END CLIENT CODE ****//

            // Proxy creates an session using the encrypted session key and IV, and the client public key (to encrypt results back to)
            int eres_createsession = enclave.enclave_session(key_enc, iv_enc, pk_client);
            //if (eres_createsession != 1) { return false; }

        }

        // Requires SetSession() and dependencies
        public void GetSessionClient()
        {
            byte[] result_session_client_key = new byte[1024];
            byte[] result_session_client_iv = new byte[1024];
            int eres_getsessionclient = enclave.enclave_get_session_client(result_session_client_key, result_session_client_iv);
            Array.Resize(ref result_session_client_key, Array.FindLastIndex(result_session_client_key, b => b != 0) + 1);
            Array.Resize(ref result_session_client_iv, Array.FindLastIndex(result_session_client_iv, b => b != 0) + 1);

        }



        // Requires CreateEnclaveManager() only
        public void SetDBKey()
        {
            byte[] fakekey = { 61, 0, 115, 206, 63, 167, 180, 82, 175, 126, 149, 223, 79, 72, 30, 72, 61, 210, 238, 18, 143, 216, 26, 83, 28, 242, 202, 127, 228, 98, 253, 120 }; // Hardcoded CEK
            int eres_setdbkey = enclave.enclave_set_key_db_insecure(fakekey);
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
            byte[] result_preforward = new byte[1 + 32 + 16 + data_preforward.Length]; // length = versionbyte (1) + MAC (32) + IV (16) + encrypted data size
            int eres_prenclaveforward = enclave.enclave_PREForward(data_preforward, result_preforward);
            //if (eres_prenclaveforward != 1) { return null; }

            return result_preforward;
        }

        // Requires PREForward() and dependencies
        public byte[] PREBackward(byte[] data_prebackward)
        {
            byte[] result_prebackward = new byte[data_prebackward.Length];
            int eres_prenclavebackward = enclave.enclave_PREBackward(data_prebackward, result_prebackward);
            Array.Resize(ref result_prebackward, Array.FindLastIndex(result_prebackward, b => b != 0) + 1);
            //if (eres_prenclavebackward != 1) { return null; }

            return result_prebackward;
        }


        public byte[] PREBackwardDecryptOutput(byte[] result_prebackward)
        {
            // Check the session (encrypted towards public key of the client)
            byte[] sesskey = new byte[256];
            byte[] sessIV = new byte[256];
            int eres_getsession = enclave.enclave_get_session_client(sesskey, sessIV);
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
