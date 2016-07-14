using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace CryptoSamples
{
    public class HMACExamples : CryptoHashExamples
    {
        public HMACExamples(byte[] key) 
            : base(new HMACSHA256(key))
        {
        }
    }

    public class HMACExamplesTest
    {
        private const string Base64TestKey = "gZFoGneGKdgx2AWeItAFSNBIeox96uR0+VlgBFE/xNI=";
        private const string ExpectedHash = "3e4df1518cf692ceb7555524ac3659093e1e5cb91d8a60f3e40acc7533ccd2a2";
        private readonly byte[] key = Convert.FromBase64String(Base64TestKey);
        public const string PlainText = "blah blah blah";

        public HMACExamples HmacExamples;

        [SetUp]
        public void Setup()
        {
            HmacExamples = new HMACExamples(key);
        }

        [Test]
        public void CreateHashTest()
        {
            var result = HmacExamples.CreateHash(PlainText);
            var hash = BytesToString(result);
            Assert.AreEqual(ExpectedHash, hash);
            Console.WriteLine(hash);
        }

        [Test]
        public async Task CreateHashAsyncTest()
        {
            var memStream = new MemoryStream(Encoding.UTF8.GetBytes(PlainText));
            var result = await HmacExamples.CreateHashAsync(memStream);
            var hash = BytesToString(result);
            Assert.AreEqual(ExpectedHash, hash);
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
