using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System;
using System;

namespace SM4
{
    public class SM4CoreFast
    {
        private const int BlockSize = 16;
        private const int RoundCount = 32;
        private const int KeyLength = 16;

        private static readonly byte[] Sbox = new byte[256]
        {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
        };

        private static readonly uint[] FK = new uint[]
        {
        0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
        };

        private static readonly uint[] CK = new uint[32]
        {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
        };


        private static readonly uint[] T0 = new uint[256];
        private static readonly uint[] T1 = new uint[256];
        private static readonly uint[] T2 = new uint[256];
        private static readonly uint[] T3 = new uint[256];
        private static readonly uint[] TPr0 = new uint[256];
        private static readonly uint[] TPr1 = new uint[256];
        private static readonly uint[] TPr2 = new uint[256];
        private static readonly uint[] TPr3 = new uint[256];

        static SM4CoreFast()
        {
            for (int i = 0; i < 256; i++)
            {
                uint s = Sbox[i];

                T0[i] = LTrans(s << 24);

                T1[i] = LTrans(s << 16);

                T2[i] = LTrans(s << 8);

                T3[i] = LTrans(s);

                TPr0[i] = LPrimeTransform(s << 24);
                TPr1[i] = LPrimeTransform(s << 16);
                TPr2[i] = LPrimeTransform(s << 8);
                TPr3[i] = LPrimeTransform(s);
            }
        }


        private static uint LTrans(uint x)
        {
            return x ^ RotL(x, 2) ^ RotL(x, 10) ^ RotL(x, 18) ^ RotL(x, 24);
        }

        private static uint LPrimeTransform(uint x)
        {
            return x ^ RotL(x, 13) ^ RotL(x, 23);
        }

        private static uint RotL(uint x, int n) => (x << n) | (x >> (32 - n));


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint T(uint x)
        {
            return T0[(x >> 24) & 0xFF] ^
                   T1[(x >> 16) & 0xFF] ^
                   T2[(x >> 8) & 0xFF] ^
                   T3[x & 0xFF];
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint TPrime(uint x)
        {
            return TPr0[(x >> 24) & 0xFF] ^
                   TPr1[(x >> 16) & 0xFF] ^
                   TPr2[(x >> 8) & 0xFF] ^
                   TPr3[x & 0xFF];
        }

        public static uint T_Original(uint x)
        {
            uint result = 0;
            for (int i = 0; i < 4; i++)
            {
                byte b = (byte)(x >> (24 - 8 * i));
                result = (result << 8) | Sbox[b];
            }
            return result ^ RotL(result, 2) ^ RotL(result, 10) ^ RotL(result, 18) ^ RotL(result, 24);
        }

        public static uint TPrime_Original(uint x)
        {
            uint result = 0;
            for (int i = 0; i < 4; i++)
            {
                byte b = (byte)(x >> (24 - 8 * i));
                result = (result << 8) | Sbox[b];
            }
            return result ^ RotL(result, 13) ^ RotL(result, 23);
        }

        public int GetBlockSize() => BlockSize;

        public uint[] KeyExpand(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (key.Length != KeyLength)
                throw new ArgumentException($"密钥长度必须为{KeyLength}字节", nameof(key));

            uint[] K = new uint[RoundCount + 4];
            uint[] rk = new uint[RoundCount];

            for (int i = 0; i < 4; i++)
            {
                K[i] = ((uint)key[4 * i] << 24) |
                       ((uint)key[4 * i + 1] << 16) |
                       ((uint)key[4 * i + 2] << 8) |
                       (uint)key[4 * i + 3];
                K[i] ^= FK[i];
            }

            for (int i = 0; i < RoundCount; i++)
            {
                uint tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
                uint res = TPrime(tmp);
                rk[i] = K[i] ^ res;
                K[i + 4] = rk[i];
            }

            return rk;
        }

        public byte[] EncryptBlock(byte[] input, uint[] rk)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (input.Length != BlockSize)
                throw new ArgumentException($"输入必须为{BlockSize}字节", nameof(input));
            if (rk == null || rk.Length != RoundCount)
                throw new ArgumentException($"轮密钥数组长度必须为{RoundCount}", nameof(rk));

            uint[] X = new uint[RoundCount + 4];
            for (int i = 0; i < 4; i++)
            {
                X[i] = ((uint)input[4 * i] << 24) |
                       ((uint)input[4 * i + 1] << 16) |
                       ((uint)input[4 * i + 2] << 8) |
                       (uint)input[4 * i + 3];
            }

            for (int i = 0; i < RoundCount; i++)
            {
                uint tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
                uint res = T(tmp);
                X[i + 4] = X[i] ^ res;
            }

            byte[] output = new byte[BlockSize];
            for (int i = 0; i < 4; i++)
            {
                uint val = X[RoundCount + 3 - i];
                output[4 * i] = (byte)(val >> 24);
                output[4 * i + 1] = (byte)(val >> 16);
                output[4 * i + 2] = (byte)(val >> 8);
                output[4 * i + 3] = (byte)val;
            }

            return output;
        }

        public byte[] DecryptBlock(byte[] input, uint[] rk)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (input.Length != BlockSize)
                throw new ArgumentException($"输入必须为{BlockSize}字节", nameof(input));
            if (rk == null || rk.Length != RoundCount)
                throw new ArgumentException($"轮密钥数组长度必须为{RoundCount}", nameof(rk));

            uint[] revRk = new uint[RoundCount];
            Array.Copy(rk, revRk, RoundCount);
            Array.Reverse(revRk);
            return EncryptBlock(input, revRk);
        }


        public byte[] EncryptEcb(byte[] input, byte[] key)
        {
            if (input.Length != BlockSize)
                throw new ArgumentException("ECB模式输入必须是16字节");

            uint[] rk = KeyExpand(key);
            return EncryptBlock(input, rk);
        }

        public byte[] EncryptCbc(byte[] input, byte[] key, byte[] iv)
        {
            if (input == null || input.Length % BlockSize != 0)
                throw new ArgumentException("输入长度必须是16的整数倍");
            if (iv == null || iv.Length != BlockSize)
                throw new ArgumentException("IV必须16字节");

            uint[] rk = KeyExpand(key);
            byte[] output = new byte[input.Length];
            byte[] prevBlock = (byte[])iv.Clone();

            for (int i = 0; i < input.Length; i += BlockSize)
            {
                byte[] xorBlock = new byte[BlockSize];
                for (int j = 0; j < BlockSize; j++)
                    xorBlock[j] = (byte)(input[i + j] ^ prevBlock[j]);

                byte[] cipherBlock = EncryptBlock(xorBlock, rk);
                Buffer.BlockCopy(cipherBlock, 0, output, i, BlockSize);
                prevBlock = cipherBlock;
            }
            return output;
        }

        public byte[] DecryptCbc(byte[] input, byte[] key, byte[] iv)
        {
            if (input == null || input.Length % BlockSize != 0)
                throw new ArgumentException("输入长度必须是16的整数倍");
            if (iv == null || iv.Length != BlockSize)
                throw new ArgumentException("IV必须16字节");

            uint[] rk = KeyExpand(key);
            uint[] revRk = rk.Reverse().ToArray();
            byte[] output = new byte[input.Length];
            byte[] prevBlock = (byte[])iv.Clone();

            for (int i = 0; i < input.Length; i += BlockSize)
            {
                byte[] cipherBlock = new byte[BlockSize];
                Buffer.BlockCopy(input, i, cipherBlock, 0, BlockSize);

                byte[] plainBlock = EncryptBlock(cipherBlock, revRk);
                for (int j = 0; j < BlockSize; j++)
                    output[i + j] = (byte)(plainBlock[j] ^ prevBlock[j]);
                prevBlock = cipherBlock;
            }
            return output;
        }
    }

    public class SM4Parallel
    {
        private readonly SM4CoreFast _sm4 = new SM4CoreFast();
        private readonly uint[] _rk;

        public SM4Parallel(byte[] key)
        {
            _rk = _sm4.KeyExpand(key);
        }

        /// <summary>
        /// 并行加密多个独立块（ECB 模式）
        /// </summary>
        public byte[][] EncryptBlocksParallel(byte[][] plainBlocks)
        {
            var cipherBlocks = new byte[plainBlocks.Length][];

            Parallel.For(0, plainBlocks.Length, i =>
            {
                cipherBlocks[i] = _sm4.EncryptBlock(plainBlocks[i], _rk);
            });

            return cipherBlocks;
        }

        /// <summary>
        /// 并行加密大文件（分块）
        /// </summary>
        public byte[] EncryptLargeData(byte[] data, byte[] iv)
        {
            // 补位
            int padLen = 16 - (data.Length % 16);
            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);
            for (int i = 0; i < padLen; i++)
                padded[data.Length + i] = (byte)padLen;

            int blockCount = padded.Length / 16;
            var plainBlocks = new byte[blockCount][];
            var cipherBlocks = new byte[blockCount][];

            for (int i = 0; i < blockCount; i++)
            {
                plainBlocks[i] = new byte[16];
                Buffer.BlockCopy(padded, i * 16, plainBlocks[i], 0, 16);
            }

            // 并行加密（注意：CBC 模式不能完全并行，这里用 ECB 方式）
            Parallel.For(0, blockCount, i =>
            {
                cipherBlocks[i] = _sm4.EncryptBlock(plainBlocks[i], _rk);
            });

            // 合并结果
            byte[] result = new byte[padded.Length];
            for (int i = 0; i < blockCount; i++)
            {
                Buffer.BlockCopy(cipherBlocks[i], 0, result, i * 16, 16);
            }

            return result;
        }
    }
}





