using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace CryptoSamples
{
    public class AESexamples
    {
        public readonly byte[] AesKey;
        public byte[] IV { get { return Aes.IV; } }
        private readonly Aes Aes;

        public AESexamples(byte[] aesKey = null, byte[] iv = null)
        {
            AesKey = aesKey ?? GenerateKey();
            Aes = AesManaged.Create();
            Aes.Mode = CipherMode.CBC; //Cipher Block Chaining, requires IV, some parallel
            //Aes.Mode = CipherMode.CFB; //Cipher Feedback, requires IV
            //Aes.Mode = CipherMode.CTS; //Cipher text stealing, Same as CBC except for last 2 blocks. requires IV
            //Aes.Mode = CipherMode.OFB; //The Output Feedback, requires IV, no parallel
            if (!Aes.ValidKeySize(AesKey.Length * 8))
                throw new ArgumentException("The encryption key is not the correct length for AES.", nameof(AesKey));

            Aes.Key = AesKey;
            if (iv == null)
            {
                Aes.GenerateIV();
            }
            else
            {
                Aes.IV = iv;
            }
        }

        public byte[] EncryptBytes(byte[] bytes)
        {
            var encryptor = Aes.CreateEncryptor();
            var memStream = new MemoryStream();
            using (memStream)
            using (var cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(bytes, 0, bytes.Length);
            }
            return memStream.ToArray();
        }

        public byte[] DecryptBytes(byte[] bytes)
        {
            var decyrptor = Aes.CreateDecryptor();
            var memstream = new MemoryStream();
            using (memstream)
            using (var cryptoStream = new CryptoStream(memstream, decyrptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(bytes, 0, bytes.Length);
            }
            return memstream.ToArray();
        }

        public async Task<byte[]> EncryptString(string plainText)
        {
            var memstream = new MemoryStream();
            using (memstream)
            {
                await EncryptString(plainText, memstream);
            }
            return memstream.ToArray();
        }

        public async Task EncryptString(string plainText, Stream stream)
        {
            var encryptor = Aes.CreateEncryptor();
            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
            using (var streamWriter = new StreamWriter(cryptoStream))
            {
                await streamWriter.WriteAsync(plainText);
            }
        }

        public async Task<string> DecryptToStringByRead(byte[] secret)
        {
            var decryptor = Aes.CreateDecryptor();
            using (var memstream = new MemoryStream(secret))
            using (var cryptoStream = new CryptoStream(memstream, decryptor, CryptoStreamMode.Read))
            using (var streamreader = new StreamReader(cryptoStream, Encoding.UTF8))
            {
                return await streamreader.ReadToEndAsync();
            }
        }

        public async Task<string> DecryptToStringByWrite(byte[] secret)
        {
            var decyrptor = Aes.CreateDecryptor();
            var memstream = new MemoryStream();
            using (memstream)
            using (var cryptoStream = new CryptoStream(memstream, decyrptor, CryptoStreamMode.Write))
            {
                await cryptoStream.WriteAsync(secret,0, secret.Length);
            }

            return Encoding.UTF8.GetString(memstream.ToArray());
        }

        public static byte[] GenerateKey()
        {
            using (var keygenerator = new AesManaged { KeySize = 256})
            {
                keygenerator.GenerateKey();
                return keygenerator.Key;
            }
        }
    }

    [TestFixture]
    public class AESexamplesTest
    {
        private const string base64TestKey = "gZFoGneGKdgx2AWeItAFSNBIeox96uR0+VlgBFE/xNI=";
        private const string base64TestIV = "b42VSBJxMAigaYZZBj8bZg==";
        private const string base64Secret = "ZQ013Q5br6IIzYxdEiUCCQ==";
        private const string plainText = "blah blah blah";
        private byte[] key = Convert.FromBase64String(base64TestKey);
        private byte[] IV = Convert.FromBase64String(base64TestIV);
        private byte[] secret = Convert.FromBase64String(base64Secret);

        [Test]
        public async Task EncryptAes()
        {
            var example = new AESexamples(key, IV);
            var testSecret = await example.EncryptString(plainText);
            CollectionAssert.AreEqual(secret, testSecret);

            var textSecret = Convert.ToBase64String(example.IV) + "&" + Convert.ToBase64String(testSecret);
            Console.WriteLine(textSecret);
        }

        [Test]
        public void EncryptBytesAes()
        {
            var example = new AESexamples(key, IV);
            var result = example.EncryptBytes(Encoding.UTF8.GetBytes(plainText));
            CollectionAssert.AreEqual(secret, result);
        }

        [Test]
        public void DecryptBytesAes()
        {
            var example = new AESexamples(key, IV);
            var result = example.DecryptBytes(secret);
            CollectionAssert.AreEqual(result, Encoding.UTF8.GetBytes(plainText));
        }

        [Test]
        public async Task DecryptAesByRead()
        {
            var example = new AESexamples(key, IV);
            var testPlainText = await example.DecryptToStringByRead(secret);
            CollectionAssert.AreEqual(plainText, testPlainText);
        }

        [Test]
        public async Task DecryptAesByWrite()
        {
            var example = new AESexamples(key, IV);
            var testPlainText = await example.DecryptToStringByWrite(secret);
            CollectionAssert.AreEqual(plainText, testPlainText);
        }

        [Test]
        public void GenerateAesKey()
        {
            var key = AESexamples.GenerateKey();
            Console.WriteLine(key.Length);
            Console.WriteLine(Convert.ToBase64String(key));
        }
    }
}
