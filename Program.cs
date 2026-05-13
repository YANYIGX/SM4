using SM4.Tests;
using System.Diagnostics;
using System.Text;

namespace SM4
{
    internal class Program
    {

        //GB/T 32907-2016 测试
        public static void Test32907()
        {           
            byte[] key = new byte[]
            {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            };

            byte[] plain = new byte[]
            {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            };

            byte[] expected = new byte[]
            {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
            };

            SM4CoreFast sm4 = new SM4CoreFast();
            uint[] rk = sm4.KeyExpand(key);
            byte[] actual = sm4.EncryptBlock(plain, rk);

            Console.WriteLine("========== GB/T 32907-2016 附录A 测试 ==========");
            Console.WriteLine($"密钥: {BitConverter.ToString(key).Replace("-", " ")}");
            Console.WriteLine($"明文: {BitConverter.ToString(plain).Replace("-", " ")}");
            Console.WriteLine($"期望: {BitConverter.ToString(expected).Replace("-", " ")}");
            Console.WriteLine($"实际: {BitConverter.ToString(actual).Replace("-", " ")}");

            bool passed = true;
            for (int i = 0; i < 16; i++)
            {
                if (actual[i] != expected[i])
                {
                    passed = false;
                    break;
                }
            }

            Console.WriteLine(passed ? "✓ 测试向量通过 (符合 GB/T 32907-2016)" : "✗ 测试向量失败");
            Console.WriteLine("==============================================");
        }


        //多线程加速测试
        public static void ParallelTest()
        {
            var key = Encoding.UTF8.GetBytes("1234567890123456");
            var iv = Encoding.UTF8.GetBytes("1234567890123456");
            var wrapper = new SM4ModeWrapper(key, SM4Mode.CTR, SM4Padding.None, iv);

            int[] sizes = { 4096, 65536, 1048576, 10485760 };

            foreach (int size in sizes)
            {
                byte[] data = new byte[size];
                Random.Shared.NextBytes(data);  
             
                byte[] dataCopy = new byte[size];
                Array.Copy(data, dataCopy, size);
               
                var sw1 = Stopwatch.StartNew();
                wrapper.EncryptInPlace(data, 0, size);
                sw1.Stop();
         
                var sw2 = Stopwatch.StartNew();
                wrapper.EncryptInPlaceParallel(dataCopy, 0, size);
                sw2.Stop();

                double speedup = (double)sw1.ElapsedMilliseconds / sw2.ElapsedMilliseconds;
                string speedupText = speedup > 1 ? $"{speedup:F2}x" : $"{speedup:F2} (实际变慢)";

                Console.WriteLine($"Size: {size / 1024,6}KB | " +
                                  $"Single: {sw1.ElapsedMilliseconds,5}ms | " +
                                  $"Parallel: {sw2.ElapsedMilliseconds,5}ms | " +
                                  $"Speedup: {speedupText}");
            }
        }


 
        static void Main(string[] args)
        {
            try
            {
             
                SM4HelperTests.RunAllTests();

             
                SM4HelperTests.TestECB();
                SM4HelperTests.TestStandardVector();
                SM4HelperTests.PerformanceBenchmark();
                SM4HelperTests.ParallelPerformanceTest();

            }
            catch (Exception e)
            {

                Console.WriteLine(e.ToString());
            }
            Console.ReadKey();

        }
    }
}
