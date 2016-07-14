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
        public const string PlainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce maximus, velit non interdum finibus, nisi ligula egestas ligula, vitae sagittis est massa interdum massa. Cras hendrerit, neque et rutrum pulvinar, purus leo finibus orci, ut sagittis ligula erat sit amet felis. Sed urna odio, tincidunt ut gravida vel, fringilla sed quam. Donec eu pulvinar leo, non molestie neque. Aenean interdum sagittis ex eu suscipit. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nunc ut mollis justo. Morbi pellentesque ligula id sapien sagittis, id luctus dolor dictum. Morbi et feugiat enim. Quisque eget porttitor nulla. Sed pharetra eu risus sed sodales. Etiam faucibus vel nulla vel blandit. Vestibulum sit amet sagittis mauris. Quisque luctus nunc eget enim suscipit vulputate.";
        public const string HashResult = "91fa92f9efa5dabdfa3917c96001a0d90b70dd41d7f18e88a25a27ca771ef1b6";
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
