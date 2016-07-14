using System;
using System.Diagnostics;
using NUnit.Framework;
using BCryptClass = BCrypt.Net.BCrypt;

namespace CryptoSamples
{
    [TestFixture]
    public class BcryptClassTest
    {
        public const string Password = "1234abcd";
        // Work factor doubles the iterations with each increase.
        public const int WorkFactor = 11;  //224 milliseconds
        //public const int WorkFactor = 12;  //525 milliseconds
        //public const int WorkFactor = 13;  //827 milliseconds
        //public const int WorkFactor = 14;  //1711 milliseconds

        [Test]
        public void BcryptHashTest()
        {
            var sw = new Stopwatch();
            sw.Start();
            var hash = BCryptClass.HashPassword(Password, WorkFactor);
            sw.Stop();
            Console.WriteLine("Hash: {0}", hash);
            Assert.True(BCryptClass.Verify(Password, hash));
            Console.WriteLine("Total milliseconds: {0}", sw.ElapsedMilliseconds);
        }
    }
}
