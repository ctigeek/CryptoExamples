using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace CryptoSamples
{
    public class CryptoHashExamples
    {
        private readonly HashAlgorithm hashAlgorithm;

        public CryptoHashExamples()
        {
            hashAlgorithm = new SHA256Managed();
        }

        protected CryptoHashExamples(HashAlgorithm hashAlgorithm)
        {
            this.hashAlgorithm = hashAlgorithm;
        }

        public byte[] CreateHash(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            return hashAlgorithm.ComputeHash(bytes);
        }

        public async Task<byte[]> CreateHashAsync(Stream stream)
        {
            //Note: If you try to do a CryptoStreamMode.Read, it will NOT work.
            using (var cryptoStream = new CryptoStream(new MemoryStream(), hashAlgorithm, CryptoStreamMode.Write))
            {
                await stream.CopyToAsync(cryptoStream);
            }
            return hashAlgorithm.Hash;
        }
    }

    [TestFixture]
    public class CryptoHashExamplesTest
    {
        public const string PlainText = "blah blah blah";
        public const string HashResult = "a74f733635a19aefb1f73e5947cef59cd7440c6952ef0f03d09d974274cbd6df";
        public CryptoHashExamples CryptoHashExamples;

        [SetUp]
        public void Setup()
        {
            CryptoHashExamples = new CryptoHashExamples();
        }

        [Test]
        public void CreateHashTest()
        {
            var result = CryptoHashExamples.CreateHash(PlainText);
            var hash = BytesToString(result);
            Assert.AreEqual(HashResult, hash);
            Console.WriteLine(hash);
        }

        [Test]
        public async Task CreateHashAsyncTest()
        {
            var memStream = new MemoryStream(Encoding.UTF8.GetBytes(PlainText));
            var result = await CryptoHashExamples.CreateHashAsync(memStream);
            var hash = BytesToString(result);
            Assert.AreEqual(HashResult, hash);
            Console.WriteLine(hash);
        }

        private static string BytesToString(byte[] array)
        {
            var sb = new StringBuilder();
            foreach (byte t in array)
            {
                sb.AppendFormat("{0:x2}", t);
            }
            return sb.ToString();
        }
    }
}
