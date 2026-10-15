# FileGuard

FileGuard 是一个简单、免费、开源的 Windows 文件加密工具，可以加密任意类型的文件。

**当前版本：V2.0** · [下载最新版](https://github.com/CuteEthanLeo/FileGuard/releases/latest)

> ## ⚠️ V1.x 用户安全公告
> V1.0 ~ V1.4 的加密格式存在严重缺陷：
> - **高级版 (AES-256-GCM)**：文件末尾保存的“密码校验值”与加密密钥完全相同，等于把密钥写进了文件，**不需要密码即可解密**。
> - **经典版 (AES-256-CFB)**：文件末尾保存了原文的 SHA-256 哈希，且没有防篡改保护。
>
> **请立即升级到 V2.0**：用 V2.0 解密旧文件（自动识别旧格式），再重新加密，然后删除旧的 `.enc` 文件。

## 功能

- **加密 / 解密**：Argon2id 密钥派生 + AES-256-GCM 分块认证加密，防篡改、防截断、抗暴力破解
- **自动识别格式**：解密时自动识别 V2.0 与 V1.x 旧文件，无需手动选择算法
- **大文件流式处理**：按 1 MiB 分块读写，内存占用恒定，带进度条
- **拖拽 / 右键菜单**：把文件拖进窗口，或在资源管理器右键选择「FileGuard 加密 / 解密」（无需管理员权限）
- **安全写入**：解密在临时文件中进行，校验全部通过才生成输出文件，密码错误不会留下半成品
- **文件粉碎**：用随机数据覆盖文件 3 次
- **文件锁定**：独占打开文件，FileGuard 运行期间其他程序无法读写
- **文件预览**：文本、Word/Excel/PowerPoint 文本内容、加密文件的格式参数

## 使用

1. 从 [Releases](https://github.com/CuteEthanLeo/FileGuard/releases/latest) 下载 `FileGuardV2.0.exe`，双击运行（免安装）。
2. **加密**：选择或拖入文件 → 输入两次密码 → 开始加密，生成 `原文件名.enc`。
3. **解密**：选择 `.enc` 文件 → 选择输出目录 → 输入密码 → 开始解密，生成 `原文件名_时间戳.扩展名`。
4. 「设置 → 右键菜单」可开启资源管理器右键菜单（Windows 11 在「显示更多选项」中）。

> 密码无法找回。忘记密码 = 文件无法恢复，请妥善保管。

## V2 文件格式

```
头部 44 字节: "FGRD" | 版本 0x02 | KDF 标识 | KDF 参数 | salt(16) | nonce 前缀(8) | 块大小 | 保留
分块:        [AES-256-GCM 密文 + 16 字节标签] × N
nonce = nonce 前缀 ‖ 块序号；AAD = 头部 ‖ 块序号 ‖ 末块标志
```

- 密钥派生：Argon2id（64 MiB 内存、3 轮、4 线程），运行环境不支持时退回 scrypt（N=2¹⁷）
- 文件中不保存任何密码校验值；密码错误时第一个分块的 GCM 校验即失败
- 头部参与每个分块的认证，修改任何字节、删除或调换分块都会被检测到

## 从源码运行 / 构建

```bash
pip install -r requirements.txt
python FileGuard/main.py
```

运行测试：

```bash
python -m unittest discover tests
```

打包为单文件 exe（输出到 `dist/`）：

```bash
pip install pyinstaller
build.bat
```

## 许可证

[GPL-3.0](LICENSE)
