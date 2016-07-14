using System;
using System.Linq;
using System.Security.Cryptography;
using NUnit.Framework;

namespace CryptoSamples
{
    public class RSAExample
    {
        public const int PROV_RSA_FULL = 1;
        private readonly string Keys;

        public RSAExample(string keys)
        {
            Keys = keys;
        }

        public byte[] Encrypt(byte[] bytes)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(Keys);
                var result = rsa.Encrypt(bytes, true);
                return result;
            }
        }

        public byte[] Decrypt(byte[] bytes)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(Keys);
                var result = rsa.Decrypt(bytes, true);
                return result;
            }
        }

        public byte[] EncryptBIG(byte[] bytes)
        {
            var aesexample = new AESexamples();
            var aeskeyAndIv = new byte[aesexample.AesKey.Length + aesexample.IV.Length];
            //TODO: include the size of the AES key.
            aesexample.AesKey.CopyTo(aeskeyAndIv, 0);
            aesexample.IV.CopyTo(aeskeyAndIv, aesexample.AesKey.Length);
            var encryptedKey = Encrypt(aeskeyAndIv);
            var sizeOfEncryptedKeys = BitConverter.GetBytes(encryptedKey.Length);

            var payload = aesexample.EncryptBytes(bytes);
            var keysAndPayload = new byte[sizeOfEncryptedKeys.Length + encryptedKey.Length + payload.Length];
            sizeOfEncryptedKeys.CopyTo(keysAndPayload, 0);
            encryptedKey.CopyTo(keysAndPayload, sizeOfEncryptedKeys.Length);
            payload.CopyTo(keysAndPayload, sizeOfEncryptedKeys.Length + encryptedKey.Length);
            return keysAndPayload;

            //TODO: Add HMAC
        }

        public byte[] DecryptBIG(byte[] bytes)
        {
            var sizeOfEncryptedKeysBytes = new byte[4];
            Array.Copy(bytes, 0, sizeOfEncryptedKeysBytes, 0, 4);
            var sizeOfEncryptedKeys = BitConverter.ToInt32(sizeOfEncryptedKeysBytes,0);
            var encryptedKey = new byte[sizeOfEncryptedKeys];
            Array.Copy(bytes, 4, encryptedKey, 0, sizeOfEncryptedKeys);
            var decryptedKeyAndIv = Decrypt(encryptedKey);
            var aesKey = new byte[32];
            var IV = new byte[16];
            Array.Copy(decryptedKeyAndIv, 0, aesKey, 0, aesKey.Length);
            Array.Copy(decryptedKeyAndIv, aesKey.Length, IV, 0, IV.Length);
            var aesexample = new AESexamples(aesKey, IV);
            var encryptedPayload = new byte[bytes.Length - (sizeOfEncryptedKeys + 4)];
            Array.Copy(bytes, sizeOfEncryptedKeys + 4, encryptedPayload, 0, encryptedPayload.Length);
            return aesexample.DecryptBytes(encryptedPayload);
        }

        public static string CreateRsaKey()
        {
            var cspParams = new CspParameters(PROV_RSA_FULL);
            cspParams.KeyContainerName = DateTime.Now.Ticks.ToString();
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.ProviderName = "Microsoft Strong Cryptographic Provider";
            using (var provider = new RSACryptoServiceProvider(2048, cspParams))
            {
                try
                {
                    // return provider.ExportParameters(true);
                    return provider.ToXmlString(true);
                }
                finally
                {
                    provider.PersistKeyInCsp = false;
                    provider.Clear();
                }
            }

        }
    }

    [TestFixture]
    public class RSAExampleTests
    {
        public const string RsaKeys =
            "<RSAKeyValue>" +
                "<Modulus>wtjOXf9RBpSRZjBPF8L7gjW4f9lHudi/g7MWAJ0gYOj51F+k4mCwbfevb/xV1ucVSZqOy94zbQtH6iUfGJSGMPGdOPqOt8b43pf4DwvzKLizGfxkl6n+IJmH/f/Tll4NUV4nvSweh+M54vJGtPCa1WQpSUZxVuxx9pL+B3n2c/PF2Fsr2jvD7B+BNfeOkZaPo27kc3y3sOrPgNAWU2ROYaDT5hhtTl961tZoNfC2Z6xEj857Qr4mA43Rcs4PGWa3OMJYHQl5616R2keAPG+YDMl/cyWKkfZAp3NahxRwet0yyQue1JoLwKt8NWKDLV9+xRbBTwQ4gUxZNPZEHSliCQ==</Modulus>" +
                "<Exponent>AQAB</Exponent>" +
                "<P>ylq1wCrgsVtBoYNqto3j2JgSHAcWnI3drvmgVf2Z/3LCgYW6BkD41u7fztxrmTxY1LCKCqm7FS6Fl9outL4zPWeYEpLJ8dWLv490ddGUvYm+zuXHnKy2KK3/nBW4vgxiJDp423DG4WrH+GQZwtAkRydT0scW2C98SqaGIZkCEOU=</P>" +
                "<Q>9oCVvVekOlGQQ1N6+MV5LFZ3kTfx5YoWQ6QE7hdGV9SuciUl2zmGF/9hvlaGQtOd3s9quw6q6gw3IzF6zcF+ozwUz/cfhfpw8xxqOiXR2/0eb8bu2X/CaTKgSJpVk2Mcd0W95KLjPCVXS7wavgmMcY0R7Q6jVwvdKDXXTNPETlU=</Q>" +
                "<DP>PNH64uGAW45kMZmAT5JiM02x077FqxRw1xCsgmwRB1iE4c1B1nNc161Ak7polMwwnuzY8M+HLZyoBrZLZ4Prfr9OU/bOv+NBd7g0dt0hab6nHSSvVIYM0jlKJK3aszShouX4QWyqOkKQDDZ6D7Xj0YceiLHSSfQr1XwrwJlup4k=</DP>" +
                "<DQ>RlEh5fRFRdmUhJAgySxTx6EW1JcX6vm8Jil4uo5rI4zpAmi0Ztf+94ODV2+JNzD0nOWgNaIWgVNguypXNLCYtmniKfz9whNR+xfE+bdmKRIIh6xA4EyAoc+uR2e3N6cTLLb5V2pb1gF06IbNPh6tMIskbPI7CA67VMgfFaxnGE0=</DQ>" +
                "<InverseQ>P1bXSCIn4T0QO4DdW0rPY4QzITBu0KopN/jlPMWiexJPFNcnmVVtxFKrG6PtU1+4oK8/UKZ7f0oW6Uc+DD6hDwMRtAwlYWOBaBzYqEWpEICuOhWuhCvqYZLWPvRyN8TMJw69ipfAiOs7UZdDIDsLl6e/86ZjvJYdFwdMo3/2C5g=</InverseQ>" +
                "<D>CymFSFRrestxOUUxtsGvC7J8/L1WEv2+2keHY7wcoiiel/htt0vvjNvds0uQSv98fvW0J1Y1+dHQX3JxIa+ahhHFXmxY14rgxXcNGSbnrxtw+TS2D4vdGNbVeACF9CKJs/Gx/ZqaL3yIhlQ3punKDkj5Zi77Uw3jE8uFHX5dbHQpgyojjvdU0+rj4dIMiQxIrQcc6UFHXm61UJc//vWrkYFmILEN2PK6GSDJRivoQWePpUnlJkUusvOVdg2y4fhT5auvy2ClS5Zzr70wlzqGGDvPVH7XEIm0GkRRcc1yOFdwJmuOzPHsd4qviM5qCDYQ4d0TYZ8ollcCtAHMwMN/TQ==</D>" +
            "</RSAKeyValue>";

        private RSAExample rsaExample;

        [SetUp]
        public void Setup()
        {
            rsaExample = new RSAExample(RsaKeys);
        }

        [Test]
        public void TestEncrypt()
        {
            byte[] testData = new byte[32];
            new Random().NextBytes(testData);
            var result = rsaExample.Encrypt(testData);
            var result2 = rsaExample.Decrypt(result);
            CollectionAssert.AreEqual(testData, result2);
        }

        [Test]
        public void TestEncryptPayloadTooBig()
        {
            byte[] testData = new byte[220];
            new Random().NextBytes(testData);
            Assert.Throws<CryptographicException>(() => rsaExample.Encrypt(testData));
            //System.Security.Cryptography.CryptographicException : Bad Length.
        }

        [Test]
        public void TestEncryptBig()
        {
            byte[] testData = new byte[5000];
            new Random().NextBytes(testData);  // <<---- DO not use Random to generate AES keys!
            var result = rsaExample.EncryptBIG(testData);
            var result2 = rsaExample.DecryptBIG(result);
            CollectionAssert.AreEqual(testData, result2);
        }

        [Test]
        public void GenerateKeyTest()
        {
            var key = RSAExample.CreateRsaKey();
            Console.WriteLine(key);
        }
    }
}
