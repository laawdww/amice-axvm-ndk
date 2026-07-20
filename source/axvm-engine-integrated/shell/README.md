# axgate — axvm 前置 Stub 安全壳（门卫层）

仅做外层引导防护，**不干涉** axvm 私有 ISA、字节码调度与 `x7d` 解释路径。  
可与已完成字节码虚拟化的 SO 叠加：虚拟化负责内部逻辑，本壳负责加载前门卫。

## 六大解耦模块

| # | 模块 | 文件 | 作用 |
|---|------|------|------|
| 1 | ELF 入口 / 描述符 | `axgate_elf.*` + `constructor(90)` | 定位 `.axgate` / `AG01` 描述符，劫持早期初始化 |
| 2 | 去 IAT | `axgate_iat.*` | 仅保留 `dlopen`/`dlsym`；API 名滚动 XOR 后动态解析 |
| 3 | 反调试 | `axgate_antidebug.*` | 经动态 API 读 TracerPid（路径 XOR 混淆） |
| 4 | AES | `axgate_aes.*` | AES-128-CTR 解密镜像；`axgate_secure_wipe` 清密钥 |
| 5 | 完整性 | `axgate_integrity.*` | 解密后对明文镜像做 SHA256 比对 |
| 6 | 内存 / OEP | `axgate_mem.*` + `axgate_entry.S` | `mmap` 匿名 RW → `mprotect` RX → 清寄存器 `BR` OEP |

编排入口：`axgate_boot()`（`src/axgate_boot.c`）。

## 指纹策略

- 自定义魔数 **`AG01`**（`0x31304741`），无 UPX / VMP / Themida 等商业壳字符串与节名特征。
- 节名用 `.axgate`（短、无 vendor 串）；API 路径名 XOR 存放。

## 两种加载模式

### `MEMFD_ELF`（默认，兼容完整 `libaxvm.so`）

1. 解密到匿名私有页 → SHA256  
2. `memfd_create` + 写回 → `dlopen(/proc/self/fd/N)`  
3. `dlsym(x7d)` + `axvm_register_dispatch`（只接导出，不改 ISA）

### `FLAT_OEP`（纯 PIC 代码镜像）

1. 解密 → SHA256 → `mprotect` RX  
2. `axgate_jump_oep(map + oep_rva)`（ARM64 清 `x0–x8` 后 `br`）

## 构建

```bash
# NDK / 引擎树内（默认 ON）
cmake -DAXVM_BUILD_AXGATE=ON ...
# 产出静态库 libaxgate.a
```

链接示例：

```cmake
target_link_libraries(your_so PRIVATE axgate)
# 再编译进由 axgatepack 生成的 axgate_blob.c
```

## 打包镜像

```bash
cd shell/tools/axgatepack
go run . -in /path/to/libaxvm.so -mode memfd \
  -out axgate_blob.bin -c axgate_blob.c
```

将 `axgate_blob.c` 与 `libaxgate.a` 链入宿主 SO。  
无 `.axgate` 节时构造器静默返回，兼容未加壳产物。

## 描述符 `axgate_desc_t`（112 字节，packed）

见 `include/axgate_types.h`：`magic/version/flags`、密文偏移、AES-128 key/iv、明文 SHA256、`oep_rva`、`api_xor_key`。

## 职责边界（再次强调）

| 做 | 不做 |
|----|------|
| 反调试 / 哈希 / 解密 / RX / 跳转或 dlopen | 改写 axvm 字节码、opcode 表、解释循环 |
| 可选登记 `x7d` 分发入口 | 替换私有 ISA 执行逻辑 |
