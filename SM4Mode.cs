using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System;
using System.Collections.Generic;
using static System.Formats.Asn1.AsnWriter;
using System.Buffers;
using System.Xml.Linq;


namespace SM4
{
    public enum SM4Mode
    {
        ECB,    
        CBC,    
        CTR     
    }

  
    public enum SM4Padding
    {
        PKCS7,  
        Zero,   
        None    
    }

  
    public class SM4ModeWrapper
    {
        private readonly SM4CoreFast _core;
        private readonly SM4Mode _mode;
        private readonly SM4Padding _padding;
        private readonly byte[] _iv;
        private uint[] _rk;

        public SM4ModeWrapper(byte[] key, SM4Mode mode, SM4Padding padding = SM4Padding.PKCS7, byte[] iv = null)
        {
            if (key == null || key.Length != 16)
                throw new ArgumentException("密钥长度必须为16字节", nameof(key));

            if (mode == SM4Mode.CBC || mode == SM4Mode.CTR)
            {
                if (iv == null || iv.Length != 16)
                    throw new ArgumentException($"初始化向量(IV)长度必须为16字节", nameof(iv));
            }

            _core = new SM4CoreFast();
            _mode = mode;
            _padding = padding;
            _iv = iv?.Clone() as byte[];
            _rk = _core.KeyExpand(key);
        }

     
        public byte[] Encrypt(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];

            if (_mode == SM4Mode.CTR)
            {
                return EncryptCTR(data);
            }
            // 处理填充
            byte[] paddedData = ApplyPadding(data, true);
            int blockCount = paddedData.Length / 16;
            List<byte> result = new List<byte>();

            switch (_mode)
            {
                case SM4Mode.ECB:
                    result.AddRange(EncryptECB(paddedData, blockCount));
                    break;
                case SM4Mode.CBC:
                    result.AddRange(EncryptCBC(paddedData, blockCount));
                    break;
                case SM4Mode.CTR:                   
                    return EncryptCTR(data);
                default:
                    throw new NotSupportedException($"不支持的模式: {_mode}");
            }

            return result.ToArray();
        }

        public byte[] Decrypt(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[0];

            if (_mode == SM4Mode.CTR)
            {
                return DecryptCTR(data);
            }

            if (data.Length % 16 != 0)
                throw new ArgumentException("密文长度必须是16的倍数", nameof(data));


            int blockCount = data.Length / 16;
            byte[] decrypted;

            switch (_mode)
            {
                case SM4Mode.ECB:
                    decrypted = DecryptECB(data, blockCount);
                    break;
                case SM4Mode.CBC:
                    decrypted = DecryptCBC(data, blockCount);
                    break;
                case SM4Mode.CTR:
                    return DecryptCTR(data);
                default:
                    throw new NotSupportedException($"不支持的模式: {_mode}");
            }
         
            return RemovePadding(decrypted);
        }

        public void EncryptInPlace(byte[] buffer, long fileOffset, int length)
        {
            if (_mode != SM4Mode.CTR)
                throw new InvalidOperationException("此方法仅适用于CTR模式");

            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (length < 0 || length > buffer.Length) throw new ArgumentOutOfRangeException(nameof(length));
            if (length == 0) return;

            int startOffset = (int)(fileOffset % 16);
            long startBlockIndex = fileOffset / 16;
            int blocks = (startOffset + length + 15) / 16;

            byte[] counter = new byte[16];
            byte[] keystream = new byte[16];

            for (int i = 0; i < blocks; i++)
            {
                long currentBlockIndex = startBlockIndex + i;
       
                Buffer.BlockCopy(_iv, 0, counter, 0, 12);
                counter[12] = (byte)(currentBlockIndex >> 24);
                counter[13] = (byte)(currentBlockIndex >> 16);
                counter[14] = (byte)(currentBlockIndex >> 8);
                counter[15] = (byte)currentBlockIndex;

            
                keystream = _core.EncryptBlock(counter, _rk);
          
                int blockStart = (i == 0) ? startOffset : 0;
                int blockEnd = (i == blocks - 1)
                    ? Math.Min(16, startOffset + length - i * 16)
                    : 16;

           
                for (int j = blockStart; j < blockEnd; j++)
                {
                    int bufferIndex = i * 16 + j - startOffset;
                    if (bufferIndex >= 0 && bufferIndex < length)
                    {
                        buffer[bufferIndex] ^= keystream[j];
                    }
                }
            }
        }      

        public void EncryptInPlaceParallel(byte[] buffer, long fileOffset, int length)
        {
            if (_mode != SM4Mode.CTR)
                throw new InvalidOperationException("此方法仅适用于CTR模式");

            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (length < 0 || length > buffer.Length) throw new ArgumentOutOfRangeException(nameof(length));
            if (length == 0) return;

            int startOffset = (int)(fileOffset % 16);
            long startBlockIndex = fileOffset / 16;
            int blocks = (startOffset + length + 15) / 16;

         
            var threadLocalPool = new ThreadLocal<(byte[] counter, byte[] keystream)>(() =>
            {
                return (new byte[16], new byte[16]);
            });

            Parallel.For(0, blocks, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
            {
                var (counter, keystream) = threadLocalPool.Value;

         
                Buffer.BlockCopy(_iv, 0, counter, 0, 12);
                long blockIndex = startBlockIndex + i;
                counter[12] = (byte)(blockIndex >> 24);
                counter[13] = (byte)(blockIndex >> 16);
                counter[14] = (byte)(blockIndex >> 8);
                counter[15] = (byte)blockIndex;

               
                byte[] encrypted = _core.EncryptBlock(counter, _rk);
                Buffer.BlockCopy(encrypted, 0, keystream, 0, 16);

            
                int blockStartInKeystream = (i == 0) ? startOffset : 0;
                int blockEndInKeystream = (i == blocks - 1)
                    ? Math.Min(16, startOffset + length - i * 16)
                    : 16;

                for (int j = blockStartInKeystream; j < blockEndInKeystream; j++)
                {
                    int bufferIndex = i * 16 + j - startOffset;
                    if (bufferIndex >= 0 && bufferIndex < length)
                    {
                        buffer[bufferIndex] ^= keystream[j];
                    }
                }
            });
        }
        public void EncryptInPlaceParallelArrayPool(byte[] buffer, long fileOffset, int length)
        {
            if (_mode != SM4Mode.CTR)
                throw new InvalidOperationException("此方法仅适用于CTR模式");

            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (length < 0 || length > buffer.Length) throw new ArgumentOutOfRangeException(nameof(length));
            if (length == 0) return;

            // 小数据直接单线程
            if (length < 256 * 1024)
            {
                EncryptInPlace(buffer, fileOffset, length);
                return;
            }

            int startOffset = (int)(fileOffset % 16);
            long startBlockIndex = fileOffset / 16;
            int blocks = (startOffset + length + 15) / 16;

            var pool = ArrayPool<byte>.Shared;

            Parallel.For(0, blocks, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
            {
                byte[] counter = pool.Rent(16);
                byte[] keystream = pool.Rent(16);

                try
                {
                    // 构造 counter
                    Buffer.BlockCopy(_iv, 0, counter, 0, 12);
                    long blockIndex = startBlockIndex + i;
                    counter[12] = (byte)(blockIndex >> 24);
                    counter[13] = (byte)(blockIndex >> 16);
                    counter[14] = (byte)(blockIndex >> 8);
                    counter[15] = (byte)blockIndex;

                    // 生成密钥流
                    byte[] encrypted = _core.EncryptBlock(counter, _rk);
                    Buffer.BlockCopy(encrypted, 0, keystream, 0, 16);

                    // 应用 XOR
                    int blockStart = (i == 0) ? startOffset : 0;
                    int blockEnd = (i == blocks - 1)
                        ? Math.Min(16, startOffset + length - i * 16)
                        : 16;

                    for (int j = blockStart; j < blockEnd; j++)
                    {
                        int bufferIndex = i * 16 + j - startOffset;
                        if (bufferIndex >= 0 && bufferIndex < length)
                        {
                            buffer[bufferIndex] ^= keystream[j];
                        }
                    }
                }
                finally
                {
                    pool.Return(counter);
                    pool.Return(keystream);
                }
            });
        }

        public void EncryptInPlaceAdaptive(byte[] buffer, long fileOffset, int length)
        {
           
            const int PARALLEL_THRESHOLD = 8 * 1024 * 1024; 
            if (length < PARALLEL_THRESHOLD)
            {          
                EncryptInPlace(buffer, fileOffset, length);
            }
            else
            {               
                EncryptInPlaceParallel(buffer, fileOffset, length);
            }
        }
      
        public byte[] EncryptParallel(byte[] data, int maxDegreeOfParallelism = -1)
        {
            if (data == null || data.Length == 0)
                return new byte[0];

            if (_mode == SM4Mode.CBC)
                throw new InvalidOperationException("CBC 模式不支持并行加密（存在链式依赖），请使用 ECB 或 CTR 模式");

            byte[] paddedData = ApplyPadding(data, true);
            int blockCount = paddedData.Length / 16;

            if (blockCount < 100) 
                return Encrypt(data);

            byte[] result = new byte[paddedData.Length];
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = maxDegreeOfParallelism == -1 ? Environment.ProcessorCount : maxDegreeOfParallelism
            };

            if (_mode == SM4Mode.ECB)
            {         
                Parallel.For(0, blockCount, parallelOptions, i =>
                {
                    byte[] block = new byte[16];
                    Buffer.BlockCopy(paddedData, i * 16, block, 0, 16);
                    byte[] encrypted = _core.EncryptBlock(block, _rk);
                    Buffer.BlockCopy(encrypted, 0, result, i * 16, 16);
                });
            }
            else if (_mode == SM4Mode.CTR)
            {               
                var keystreams = new byte[blockCount][];
                Parallel.For(0, blockCount, parallelOptions, i =>
                {
                    byte[] counter = new byte[16];
                    Buffer.BlockCopy(_iv, 0, counter, 0, 12);
                    counter[12] = (byte)(i >> 24);
                    counter[13] = (byte)(i >> 16);
                    counter[14] = (byte)(i >> 8);
                    counter[15] = (byte)i;
                    keystreams[i] = _core.EncryptBlock(counter, _rk);
                });
             
                for (int i = 0; i < blockCount; i++)
                {
                    int offset = i * 16;
                    int remaining = Math.Min(16, paddedData.Length - offset);
                    for (int j = 0; j < remaining; j++)
                    {
                        result[offset + j] = (byte)(paddedData[offset + j] ^ keystreams[i][j]);
                    }
                }
            }

            return result;
        }

        public byte[] DecryptParallel(byte[] data, int maxDegreeOfParallelism = -1)
        {
            if (data == null || data.Length == 0)
                return new byte[0];

            if (data.Length % 16 != 0)
                throw new ArgumentException("密文长度必须是16的倍数", nameof(data));

            int blockCount = data.Length / 16;

            if (_mode == SM4Mode.CBC && blockCount < 100)
                return Decrypt(data);

            byte[] decrypted = new byte[data.Length];
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = maxDegreeOfParallelism == -1 ? Environment.ProcessorCount : maxDegreeOfParallelism
            };

            if (_mode == SM4Mode.ECB)
            {                
                Parallel.For(0, blockCount, parallelOptions, i =>
                {
                    byte[] block = new byte[16];
                    Buffer.BlockCopy(data, i * 16, block, 0, 16);
                    byte[] decryptedBlock = _core.DecryptBlock(block, _rk);
                    Buffer.BlockCopy(decryptedBlock, 0, decrypted, i * 16, 16);
                });
            }
            else if (_mode == SM4Mode.CBC)
            {
                var decryptedBlocks = new byte[blockCount][];
                Parallel.For(0, blockCount, parallelOptions, i =>
                {
                    byte[] cipherBlock = new byte[16];
                    Buffer.BlockCopy(data, i * 16, cipherBlock, 0, 16);
                    decryptedBlocks[i] = _core.DecryptBlock(cipherBlock, _rk);
                });

                // 合并结果（单线程 XOR IV/前一个密文块）
                byte[] prevBlock = _iv.Clone() as byte[];
                for (int i = 0; i < blockCount; i++)
                {
                    for (int j = 0; j < 16; j++)
                        decrypted[i * 16 + j] = (byte)(decryptedBlocks[i][j] ^ prevBlock[j]);

                    // 下一个块使用当前密文块作为 IV
                    Buffer.BlockCopy(data, i * 16, prevBlock, 0, 16);
                }
            }
            else if (_mode == SM4Mode.CTR)
            {
                // CTR 解密与加密相同
                return EncryptParallel(data, maxDegreeOfParallelism);
            }

            return RemovePadding(decrypted);
        }

        public void ProcessStreamParallel(Stream inputStream, Stream outputStream,
                                   int bufferSize = 1024 * 1024, bool isEncrypt = true)
        {
            if (_mode == SM4Mode.CBC)
                throw new InvalidOperationException("CBC 模式不支持流式并行处理");

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            // 读取所有数据到内存
            using var ms = new MemoryStream();
            inputStream.CopyTo(ms);
            byte[] allData = ms.ToArray();

            // 应用填充（加密时）或直接使用（解密时）
            byte[] processedData = ApplyPadding(allData, isEncrypt);

            // 计算总块数
            int totalBlocks = processedData.Length / 16;

            // 准备块数组
            var blocks = new byte[totalBlocks][];
            for (int i = 0; i < totalBlocks; i++)
            {
                blocks[i] = new byte[16];
                Buffer.BlockCopy(processedData, i * 16, blocks[i], 0, 16);
            }

            // 并行加密/解密
            var results = new byte[totalBlocks][];
            Parallel.For(0, totalBlocks, parallelOptions, i =>
            {
                if (isEncrypt)
                    results[i] = _core.EncryptBlock(blocks[i], _rk);
                else
                    results[i] = _core.DecryptBlock(blocks[i], _rk);
            });

            // 合并结果
            byte[] outputData = new byte[totalBlocks * 16];
            for (int i = 0; i < totalBlocks; i++)
            {
                Buffer.BlockCopy(results[i], 0, outputData, i * 16, 16);
            }

            // 解密时去除填充
            if (!isEncrypt)
            {
                outputData = RemovePadding(outputData);
            }

            // 写入输出流
            outputStream.Write(outputData, 0, outputData.Length);
        }


 
        public static ParallelPerformanceInfo GetParallelPerformanceInfo(int dataSizeMB)
        {
            double singleThreadTime = dataSizeMB * 1000.0 / 450; // 450 MB/s
            int cpuCores = Environment.ProcessorCount;
            double parallelTime = singleThreadTime / cpuCores;
            double speedUp = cpuCores;

            return new ParallelPerformanceInfo
            {
                DataSizeMB = dataSizeMB,
                CpuCores = cpuCores,
                EstimatedSingleThreadMS = singleThreadTime,
                EstimatedParallelMS = parallelTime,
                ExpectedSpeedUp = speedUp,
                RecommendedMode = cpuCores >= 4 ? "并行" : "单线程"
            };
        }

        #region 私有方法

        private byte[] EncryptECB(byte[] data, int blockCount)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[16];
                Array.Copy(data, i * 16, block, 0, 16);
                byte[] encrypted = _core.EncryptBlock(block, _rk);
                Array.Copy(encrypted, 0, result, i * 16, 16);
            }
            return result;
        }

        private byte[] DecryptECB(byte[] data, int blockCount)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[16];
                Array.Copy(data, i * 16, block, 0, 16);
                byte[] decrypted = _core.DecryptBlock(block, _rk);
                Array.Copy(decrypted, 0, result, i * 16, 16);
            }
            return result;
        }

        private byte[] EncryptCBC(byte[] data, int blockCount)
        {
            byte[] result = new byte[data.Length];
            byte[] prevBlock = _iv.Clone() as byte[];

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[16];
                Array.Copy(data, i * 16, block, 0, 16);

                // XOR with previous ciphertext
                for (int j = 0; j < 16; j++)
                    block[j] ^= prevBlock[j];

                byte[] encrypted = _core.EncryptBlock(block, _rk);
                Array.Copy(encrypted, 0, result, i * 16, 16);
                prevBlock = encrypted;
            }
            return result;
        }

        private byte[] DecryptCBC(byte[] data, int blockCount)
        {
            byte[] result = new byte[data.Length];
            byte[] prevBlock = _iv.Clone() as byte[];

            for (int i = 0; i < blockCount; i++)
            {
                byte[] block = new byte[16];
                Array.Copy(data, i * 16, block, 0, 16);

                byte[] decrypted = _core.DecryptBlock(block, _rk);

                // XOR with previous ciphertext
                for (int j = 0; j < 16; j++)
                    decrypted[j] ^= prevBlock[j];

                Array.Copy(decrypted, 0, result, i * 16, 16);
                prevBlock = block;
            }
            return result;
        }

        private byte[] EncryptCTR(byte[] data)
        {
            byte[] result = new byte[data.Length];
            byte[] counter = new byte[16];
            byte[] keystream = new byte[16];

            for (long i = 0; i * 16 < data.Length; i++)
            {
                // 构造 counter = [IV前12字节] + [counter大端序4字节]
                Buffer.BlockCopy(_iv, 0, counter, 0, 12);
                counter[12] = (byte)(i >> 24);
                counter[13] = (byte)(i >> 16);
                counter[14] = (byte)(i >> 8);
                counter[15] = (byte)i;

                keystream = _core.EncryptBlock(counter, _rk);

                int offset = (int)(i * 16);
                int remaining = Math.Min(16, data.Length - offset);
                for (int j = 0; j < remaining; j++)
                {
                    result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                }
            }
            return result;
        }

        private byte[] DecryptCTR(byte[] data)
        {
           
            return EncryptCTR(data);
        }

        private byte[] ApplyPadding(byte[] data, bool encrypt)
        {
            if (!encrypt) return data;

            if (_padding == SM4Padding.None)
            {
                if (data.Length % 16 != 0)
                    throw new ArgumentException("无填充模式下数据长度必须是16的倍数");
                return data;
            }

            if (_padding == SM4Padding.PKCS7)
            {
                int paddingLen = 16 - (data.Length % 16);
                byte[] padded = new byte[data.Length + paddingLen];
                Array.Copy(data, padded, data.Length);
                for (int i = 0; i < paddingLen; i++)
                    padded[data.Length + i] = (byte)paddingLen;
                return padded;
            }

            if (_padding == SM4Padding.Zero)
            {
                int paddingLen = 16 - (data.Length % 16);
                if (paddingLen == 16) paddingLen = 0;
                byte[] padded = new byte[data.Length + paddingLen];
                Array.Copy(data, padded, data.Length);
                return padded;
            }

            throw new NotSupportedException($"不支持的填充方式: {_padding}");
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (_padding == SM4Padding.None)
                return data;

            if (_padding == SM4Padding.PKCS7)
            {
                int paddingLen = data[data.Length - 1];
                if (paddingLen < 1 || paddingLen > 16)
                    throw new InvalidOperationException("无效的PKCS7填充");
                byte[] result = new byte[data.Length - paddingLen];
                Array.Copy(data, result, result.Length);
                return result;
            }

            if (_padding == SM4Padding.Zero)
            {
                int trimLen = 0;
                for (int i = data.Length - 1; i >= 0; i--)
                {
                    if (data[i] == 0)
                        trimLen++;
                    else
                        break;
                }
                if (trimLen > 0)
                {
                    byte[] result = new byte[data.Length - trimLen];
                    Array.Copy(data, result, result.Length);
                    return result;
                }
                return data;
            }

            throw new NotSupportedException($"不支持的填充方式: {_padding}");
        }

        #endregion
    }


    public struct ParallelPerformanceInfo
    {
        public int DataSizeMB { get; set; }
        public int CpuCores { get; set; }
        public double EstimatedSingleThreadMS { get; set; }
        public double EstimatedParallelMS { get; set; }
        public double ExpectedSpeedUp { get; set; }
        public string RecommendedMode { get; set; }

        public override string ToString()
        {
            return $"数据大小: {DataSizeMB} MB\n" +
                   $"CPU核心数: {CpuCores}\n" +
                   $"单线程预估: {EstimatedSingleThreadMS:F0} ms\n" +
                   $"并行预估: {EstimatedParallelMS:F0} ms\n" +
                   $"加速比: {ExpectedSpeedUp:F1}x\n" +
                   $"推荐模式: {RecommendedMode}";
        }
    }
}