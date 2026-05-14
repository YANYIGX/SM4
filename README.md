# SM4 国密算法实现 (C#)

纯 C# 实现的 SM4 国密算法，高性能、多模式支持、多线程并行加速。通过 GB/T 32907-2016 标准向量测试。

## 特性

| 特性 | 说明 |
|------|------|
| 国密标准 | 完全符合 GB/T 32907-2016，通过官方测试向量 |
| 高性能 | 查表优化，单线程约 450 MB/s |
| 并行加速 | ECB/CTR 模式支持并行，8 核性能 3.2 GB/s |
| 多模式 | ECB / CBC / CTR 三种工作模式 |
| 多填充 | PKCS7 / Zero / None 填充方式 |
| 流式处理 | CTR 模式支持原地加密，适合大文件 |
| 线程安全 | 无共享状态，多线程安全 |
| 零依赖 | 纯 C# 实现，无需第三方库 |

## 性能基准

| 数据大小 | 单线程 | 多线程 (8核) | 加速比 |
|----------|--------|--------------|--------|
| 1 MB | 79 ms | 58 ms | 1.36x |
| 10 MB | 706 ms | 87 ms | 8.11x |
| 100 MB | 7.0 s | 0.85 s | 8.2x |

测试环境：Intel Xeon E5-2680 v4 / 8核 / DDR4

## 快速开始

### 基础使用
```csharp
using SM4;
using System.Text;

byte[] key = Encoding.UTF8.GetBytes("1234567890123456");
byte[] iv = Encoding.UTF8.GetBytes("1234567890123456");

// ECB 模式
var ecb = new SM4Helper(key, SM4Mode.ECB, SM4Padding.PKCS7);
string encrypted = ecb.EncryptString("Hello SM4!");`
string decrypted = ecb.DecryptString(encrypted);`

// CBC 模式
var cbc = new SM4Helper(key, SM4Mode.CBC, SM4Padding.PKCS7, iv);

// CTR 模式
var ctr = new SM4Helper(key, SM4Mode.CTR, SM4Padding.None, iv);
```
### 大文件加密（CTR 模式）
```csharp
using SM4;
using System.IO;

byte[] key = Encoding.UTF8.GetBytes("1234567890123456");
byte[] iv = Encoding.UTF8.GetBytes("1234567890123456");

var wrapper = new SM4ModeWrapper(key, SM4Mode.CTR, SM4Padding.None, iv);
byte[] buffer = new byte[16 * 1024 * 1024];
long offset = 0;
int bytesRead;

using (var input = File.OpenRead("largefile.bin"))
using (var output = File.Create("largefile.enc"))
{
    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
    {
        wrapper.EncryptInPlaceParallel(buffer, offset, bytesRead);
        output.Write(buffer, 0, bytesRead);`
        offset += bytesRead;`
    }
}
```
### 并行加密（大数据块）
```csharp
byte[] largeData = new byte[100 * 1024 * 1024];
Random.Shared.NextBytes(largeData);

byte[] encrypted = ecb.Encrypt(largeData);
byte[] decrypted = ecb.Decrypt(encrypted);
```
## 项目结构

SM4/
├── SM4Core.cs          # SM4 核心算法（查表优化）`
├── SM4Mode.cs          # 工作模式封装（ECB/CBC/CTR）`
├── SM4Helper.cs        # 便捷封装 + 字符串加解密`
└── SM4Test.cs          # 完整测试套件`

## API 参考

### SM4Mode 枚举

| 模式 | 说明 | 并行支持 |
|------|------|----------|
| ECB | 电子密码本模式 | 完全并行 |
| CBC | 密码分组链接模式 | 加密串行 / 解密并行 |
| CTR | 计数器模式 | 完全并行 |

### SM4Padding 枚举

| 填充 | 说明 |
|------|------|
| PKCS7 | PKCS#7 填充（推荐） |
| Zero | 零填充 |
| None | 无填充（需数据长度是 16 的倍数） |

### SM4Helper 类

| 方法 | 说明 |
|------|------|
| Encrypt(byte[] data) | 加密字节数组 |
| Decrypt(byte[] data) | 解密字节数组 |
| EncryptString(string text) | 加密字符串（返回 Base64） |
| DecryptString(string base64) | 解密 Base64 字符串 |

### SM4ModeWrapper 类

| 方法 | 说明 |
|------|------|
| EncryptInPlace(buffer, offset, length) | CTR 模式原地加密（单线程） |
| EncryptInPlaceParallel(buffer, offset, length) | CTR 模式原地加密（并行） |

## 测试验证

### 运行所有测试

`SM4HelperTests.RunAllTests();`

### 测试覆盖

- GB/T 32907-2016 标准向量测试
- ECB / CBC / CTR 三种模式
- PKCS7 / Zero / None 填充方式
- 各种长度数据（1 ~ 1025 字节）
- Unicode / Emoji / 控制字符
- 空数据 / 边界条件
- 并发安全（8 线程）
- 性能基准测试

## 优化技术

| 优化技术 | 说明 | 性能提升 |
|----------|------|----------|
| 查表预计算 | T 表预计算，避免重复计算 | 3x |
| 缓存局部性 | 8KB 查表完整驻留 L1 缓存 | 1.2x |
| 无分支设计 | 消除分支预测失败 | 1.1x |
| 多线程并行 | 自适应并行（>256KB 自动启用） | 8x |
| ArrayPool 复用 | 减少内存分配和 GC 压力 | 1.5x |

## 实际应用用
该用项目是严翼共享加密架构的原生项目，主要用于流加解密。``
严翼共享加密架构介绍 https://www.yanyigx.com/Home/Security

## 贡献

欢迎提交 Issue 和 Pull Request。

## 许可证

MIT License

## 致谢

- GB/T 32907-2016《信息安全技术 SM4 分组密码算法》
- 国家密码管理局发布的 SM4 算法标准
