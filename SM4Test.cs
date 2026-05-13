using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SM4.Tests
{
    public class SM4HelperTests
    {
        private static readonly byte[] TestKey = Encoding.UTF8.GetBytes("1234567890123456");
        private static readonly byte[] TestIV = Encoding.UTF8.GetBytes("1234567890123456");

        #region 基础功能测试

        /// <summary>
        /// 测试 ECB 模式加解密
        /// </summary>
        public static void TestECB()
        {
            Console.WriteLine("=== ECB 模式测试 ===");
            var helper = new SM4Helper(TestKey, SM4Mode.ECB, SM4Padding.PKCS7);

            string plainText = "Hello SM4! 这是一个测试。";
            Console.WriteLine($"原文: {plainText}");

            string encrypted = helper.EncryptString(plainText);
            Console.WriteLine($"加密(Base64): {encrypted}");

            string decrypted = helper.DecryptString(encrypted);
            Console.WriteLine($"解密: {decrypted}");

            bool passed = plainText == decrypted;
            Console.WriteLine($"结果: {(passed ? "通过" : "失败")}\n");
        }

        /// <summary>
        /// 测试 CBC 模式加解密
        /// </summary>
        public static void TestCBC()
        {
            Console.WriteLine("=== CBC 模式测试 ===");
            var helper = new SM4Helper(TestKey, SM4Mode.CBC, SM4Padding.PKCS7, TestIV);

            string plainText = "CBC模式测试，支持中文！";
            Console.WriteLine($"原文: {plainText}");

            string encrypted = helper.EncryptString(plainText);
            Console.WriteLine($"加密(Base64): {encrypted}");

            string decrypted = helper.DecryptString(encrypted);
            Console.WriteLine($"解密: {decrypted}");

            bool passed = plainText == decrypted;
            Console.WriteLine($"结果: {(passed ? "通过" : "失败")}\n");
        }

        /// <summary>
        /// 测试 CTR 模式加解密
        /// </summary>
        public static void TestCTR()
        {
            Console.WriteLine("=== CTR 模式测试 ===");
            var helper = new SM4Helper(TestKey, SM4Mode.CTR, SM4Padding.None, TestIV);

            string plainText = "CTR流式加密测试，这是一个很长的测试字符串，用于验证流式加密的正确性。";
            Console.WriteLine($"原文: {plainText}");

            string encrypted = helper.EncryptString(plainText);
            Console.WriteLine($"加密(Base64): {encrypted}");

            string decrypted = helper.DecryptString(encrypted);
            Console.WriteLine($"解密: {decrypted}");

            bool passed = plainText == decrypted;
            Console.WriteLine($"结果: {(passed ? "通过" : "失败")}\n");
        }

        /// <summary>
        /// 测试空数据
        /// </summary>
        public static void TestEmptyData()
        {
            Console.WriteLine("=== 空数据测试 ===");
            var helper = new SM4Helper(TestKey, SM4Mode.ECB);

            byte[] empty = new byte[0];
            byte[] encrypted = helper.Encrypt(empty);
            byte[] decrypted = helper.Decrypt(encrypted);

            bool passed = encrypted.Length == 0 && decrypted.Length == 0;
            Console.WriteLine($"空数据加解密: {(passed ? "通过" : "失败")}\n");
        }

        /// <summary>
        /// 测试大数据（验证并行）
        /// </summary>
        public static void TestLargeData()
        {
            Console.WriteLine("=== 大数据测试 (10MB) ===");
            var helper = new SM4Helper(TestKey, SM4Mode.CTR, SM4Padding.None, TestIV);

            // 生成 10MB 测试数据
            int size = 10 * 1024 * 1024;
            byte[] original = new byte[size];
            Random.Shared.NextBytes(original);

            var sw = Stopwatch.StartNew();
            byte[] encrypted = helper.Encrypt(original);
            sw.Stop();
            Console.WriteLine($"加密耗时: {sw.ElapsedMilliseconds}ms, 速度: {size / 1024.0 / 1024 / (sw.ElapsedMilliseconds / 1000.0):F2} MB/s");

            sw.Restart();
            byte[] decrypted = helper.Decrypt(encrypted);
            sw.Stop();
            Console.WriteLine($"解密耗时: {sw.ElapsedMilliseconds}ms, 速度: {size / 1024.0 / 1024 / (sw.ElapsedMilliseconds / 1000.0):F2} MB/s");

            bool passed = original.SequenceEqual(decrypted);
            Console.WriteLine($"数据一致性: {(passed ? "通过" : "失败")}\n");
        }

        #endregion

        #region 标准向量测试

        /// <summary>
        /// GB/T 32907-2016 标准向量测试
        /// </summary>
        public static void TestStandardVector()
        {
            Console.WriteLine("=== GB/T 32907-2016 标准向量测试 ===");

            // 标准测试向量
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

            var helper = new SM4Helper(key, SM4Mode.ECB, SM4Padding.None);
            byte[] actual = helper.Encrypt(plain);

            bool passed = actual.SequenceEqual(expected);
            Console.WriteLine($"期望: {BitConverter.ToString(expected)}");
            Console.WriteLine($"实际: {BitConverter.ToString(actual)}");
            Console.WriteLine($"结果: {(passed ? "通过" : "失败")}\n");
        }

        #endregion

        #region 模式兼容性测试

        /// <summary>
        /// 测试不同模式间的互操作性
        /// </summary>
        public static void TestModeInterop()
        {
            Console.WriteLine("=== 模式互操作性测试 ===");

            string plainText = "不同模式加密结果应该不同";

            var ecbHelper = new SM4Helper(TestKey, SM4Mode.ECB, SM4Padding.PKCS7);
            var cbcHelper = new SM4Helper(TestKey, SM4Mode.CBC, SM4Padding.PKCS7, TestIV);
            var ctrHelper = new SM4Helper(TestKey, SM4Mode.CTR, SM4Padding.None, TestIV);

            string ecbEnc = ecbHelper.EncryptString(plainText);
            string cbcEnc = cbcHelper.EncryptString(plainText);
            string ctrEnc = ctrHelper.EncryptString(plainText);

            Console.WriteLine($"ECB加密: {ecbEnc}");
            Console.WriteLine($"CBC加密: {cbcEnc}");
            Console.WriteLine($"CTR加密: {ctrEnc}");

            // 三种模式加密结果应该都不同
            bool allDifferent = ecbEnc != cbcEnc && cbcEnc != ctrEnc && ecbEnc != ctrEnc;
            Console.WriteLine($"三种模式结果均不同: {(allDifferent ? "是" : "否")}\n");
        }

        /// <summary>
        /// 测试相同数据重复加密结果不同（CBC模式有随机IV）
        /// </summary>
        public static void TestRandomIV()
        {
            Console.WriteLine("=== 随机IV效果测试 ===");

            string plainText = "相同明文，不同IV加密结果应该不同";

            // 注意：这里 IV 固定，实际使用应该每次生成随机 IV
            var helper1 = new SM4Helper(TestKey, SM4Mode.CBC, SM4Padding.PKCS7, TestIV);
            var helper2 = new SM4Helper(TestKey, SM4Mode.CBC, SM4Padding.PKCS7, TestIV);

            string enc1 = helper1.EncryptString(plainText);
            string enc2 = helper2.EncryptString(plainText);

            bool sameIVSameResult = enc1 == enc2;
            Console.WriteLine($"相同IV相同结果: {(sameIVSameResult ? "是" : "否")}");
            Console.WriteLine($"加密1: {enc1}");
            Console.WriteLine($"加密2: {enc2}\n");
        }

        #endregion

        #region 边界条件测试

        /// <summary>
        /// 测试各种长度数据的加解密
        /// </summary>
        public static void TestVariousLengths()
        {
            Console.WriteLine("=== 边界长度测试 ===");
            var helper = new SM4Helper(TestKey, SM4Mode.CBC, SM4Padding.PKCS7, TestIV);

            int[] lengths = { 1, 7, 8, 15, 16, 17, 31, 32, 33, 100, 1023, 1024, 1025 };
            bool allPassed = true;

            foreach (int len in lengths)
            {
                string testData = new string('A', len);
                string encrypted = helper.EncryptString(testData);
                string decrypted = helper.DecryptString(encrypted);

                bool passed = testData == decrypted;
                allPassed &= passed;
                Console.WriteLine($"长度 {len,4}: {(passed ? "OK" : "Err")} 原文: {testData[..Math.Min(10, testData.Length)]}...");
            }
            Console.WriteLine($"所有长度测试: {(allPassed ? "通过" : "失败")}\n");
        }

        /// <summary>
        /// 测试特殊字符
        /// </summary>
        public static void TestSpecialCharacters()
        {
            Console.WriteLine("=== 特殊字符测试 ===");
            var helper = new SM4Helper(TestKey, SM4Mode.CBC, SM4Padding.PKCS7, TestIV);

            string[] testStrings = {
                "Hello World!",
                "你好，世界！",
                "Mixed 中英 123 !@#",
                "🎉🎊🎈✨🌟",
                "\"quotes\", 'quotes', <tags>, &amp;",
                "Line1\nLine2\r\nTab\tEnd",
                "  前导空格  后置空格  ",
                "一\n二\n三\n四",
                "null字符: \0 测试",
                "很长很长很长很长很长很长很长很长很长很长很长很长的字符串"
            };

            bool allPassed = true;
            foreach (string original in testStrings)
            {
                string encrypted = helper.EncryptString(original);
                string decrypted = helper.DecryptString(encrypted);

                bool passed = original == decrypted;
                allPassed &= passed;
                Console.WriteLine($"原文: {original} → {(passed ? "OK" : "Err")}");
            }
            Console.WriteLine($"所有特殊字符测试: {(allPassed ? "通过" : "失败")}\n");
        }

        #endregion

        #region 性能测试

        /// <summary>
        /// 性能基准测试
        /// </summary>
        public static void PerformanceBenchmark()
        {
            Console.WriteLine("=== 性能基准测试 ===");

            int[] sizes = { 1024, 10240, 102400, 1048576, 10485760 };

            Console.WriteLine($"{"大小",10} | {"加密耗时",12} | {"解密耗时",12} | {"加密速度",12} | {"解密速度",12}");
            Console.WriteLine(new string('-', 65));

            foreach (int size in sizes)
            {
                byte[] data = new byte[size];
                Random.Shared.NextBytes(data);

                var helper = new SM4Helper(TestKey, SM4Mode.CTR, SM4Padding.None, TestIV);

                // 加密性能
                var sw = Stopwatch.StartNew();
                byte[] encrypted = helper.Encrypt(data);
                sw.Stop();
                double encSpeed = size / 1024.0 / 1024 / (sw.ElapsedMilliseconds / 1000.0);

                // 解密性能
                sw.Restart();
                byte[] decrypted = helper.Decrypt(encrypted);
                sw.Stop();
                double decSpeed = size / 1024.0 / 1024 / (sw.ElapsedMilliseconds / 1000.0);

                Console.WriteLine($"{size,10} | {sw.ElapsedMilliseconds,10}ms | {sw.ElapsedMilliseconds,10}ms | {encSpeed,10:F2}MB/s | {decSpeed,10:F2}MB/s");
            }
            Console.WriteLine();
        }

        /// <summary>
        /// 并行 vs 单线程性能对比
        /// </summary>
        public static void ParallelPerformanceTest()
        {
            Console.WriteLine("=== 并行性能对比 ===");

            int size = 10 * 1024 * 1024; // 10MB
            byte[] data = new byte[size];
            Random.Shared.NextBytes(data);

            var helper = new SM4Helper(TestKey, SM4Mode.CTR, SM4Padding.None, TestIV);
            var wrapper = helper.GetModeWrapper();

            // 单线程测试
            byte[] dataCopy1 = new byte[size];
            Array.Copy(data, dataCopy1, size);
            var sw = Stopwatch.StartNew();
            wrapper.EncryptInPlace(dataCopy1, 0, size);
            sw.Stop();
            Console.WriteLine($"单线程: {sw.ElapsedMilliseconds}ms, 速度: {size / 1024.0 / 1024 / (sw.ElapsedMilliseconds / 1000.0):F2} MB/s");

            // 多线程测试
            byte[] dataCopy2 = new byte[size];
            Array.Copy(data, dataCopy2, size);
            sw.Restart();
            wrapper.EncryptInPlaceParallelArrayPool(dataCopy2, 0, size);
            sw.Stop();
            Console.WriteLine($"多线程(ArrayPool): {sw.ElapsedMilliseconds}ms, 速度: {size / 1024.0 / 1024 / (sw.ElapsedMilliseconds / 1000.0):F2} MB/s");

            // 验证一致性
            bool passed = dataCopy1.SequenceEqual(dataCopy2);
            Console.WriteLine($"结果一致性: {(passed ? "通过" : "失败")}\n");
        }

        #endregion

        #region 并发安全测试

        /// <summary>
        /// 多线程并发测试
        /// </summary>
        public static void TestConcurrency()
        {
            Console.WriteLine("=== 并发安全测试 ===");

            int threadCount = 8;
            int dataSize = 1024 * 1024; // 每线程 1MB

            var results = new bool[threadCount];

            Parallel.For(0, threadCount, i =>
            {
                try
                {
                    // 每个线程独立的 helper 实例
                    var helper = new SM4Helper(TestKey, SM4Mode.CTR, SM4Padding.None, TestIV);

                    byte[] data = new byte[dataSize];
                    Random.Shared.NextBytes(data);

                    string original = Convert.ToBase64String(data);
                    string encrypted = helper.EncryptString(original);
                    string decrypted = helper.DecryptString(encrypted);

                    results[i] = original == decrypted;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"线程 {i} 异常: {ex.Message}");
                    results[i] = false;
                }
            });

            bool allPassed = results.All(r => r);
            Console.WriteLine($"并发测试: {(allPassed ? "✅ 通过" : "❌ 失败")}");
            Console.WriteLine($"成功线程数: {results.Count(r => r)}/{threadCount}\n");
        }

        #endregion

        #region 运行所有测试

        /// <summary>
        /// 运行所有测试
        /// </summary>
        public static void RunAllTests()
        {
            Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                    SM4Helper 完整测试套件                    ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝\n");

            // 基础功能
            TestECB();
            TestCBC();
            TestCTR();
            TestEmptyData();

            // 标准验证
            TestStandardVector();

            // 兼容性
            TestModeInterop();
            TestRandomIV();

            // 边界条件
            TestVariousLengths();
            TestSpecialCharacters();

            // 性能
            PerformanceBenchmark();
            ParallelPerformanceTest();

            // 大数据
            TestLargeData();

            // 并发
            TestConcurrency();

            Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║                        测试完成                              ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        }

        #endregion
    }
}