# Embedded Logger — 技术架构文档

## 1. 系统全局架构

```
┌─────────────────────────────────────────────────────────────────┐
│                   业务进程 / 用户程序                             │
│  LOG_INFO("SD_CARD", "mount ok")  ←  主动调用宏                  │
│  signal handler                   ←  被动崩溃捕获                │
└────────────────────────┬────────────────────────────────────────┘
                         │ logger_write()
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    logger_core.c  (入口与编排)                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │ load_config_ini │  │ format_entry()   │  │ logger_set_    │ │
│  │ apply_defaults  │  │ [时间][级别]     │  │ level()        │ │
│  └────────┬────────┘  │ [PID][MODULE]msg │  └────────────────┘ │
│           │           └────────┬─────────┘                     │
└───────────┼────────────────────┼──────────────────────────────-┘
            │                    │
      配置加载                    │ 格式化后的 entry
            │            ┌───────▼────────────────────────────────┐
            │            │       logger_protection.c              │
            │            │   djb2 hash(module+message)            │
            │            │   dedup 窗口检查 → allow / suppress     │
            │            │   输出 summary ("Repeated N times")    │
            │            └───────┬────────────────────────────────┘
            │                    │ allow=true
            │       ┌────────────┼──────────────────┐
            │       ▼            ▼                  ▼
            │  ┌────────┐  ┌──────────┐   ┌────────────────────┐
            │  │storage │  │transport │   │  crash_handler     │
            │  │_write()│  │_send_log │   │  (signal 异步写)    │
            │  └───┬────┘  └────┬─────┘   └────────────────────┘
            │      │            │
            │      ▼            ▼
            │ ┌─────────┐  ┌──────────────────────────────────┐
            │ │AES-256  │  │   UDP Socket (send_fd)           │
            │ │CBC 加密 │  │   → remote_ip:remote_port        │
            │ │(可选)   │  │   PKT_LOG_ENTRY 包               │
            │ └────┬────┘  │   TransportHeader + payload      │
            │      │       │   CRC32 校验 + 可选加密           │
            │      ▼       └──────────────────────────────────┘
            │ ┌──────────────────────────────────────────────┐
            │ │  日志文件  log-YYYYMMDD-HHMMSS.txt           │
            │ │  write(2) + 4字节 length prefix              │
            │ │  max_file_size → rotation                    │
            │ │  max_total_size → 删除最旧文件                │
            │ └──────────────────────────────────────────────┘
```

---

## 2. 模块说明

### 2.1 logger_core.c — 核心编排器
- **职责**: 配置加载、模块初始化顺序管理、`logger_write()` 主流程。
- **线程安全**: 单把 `pthread_mutex_t` 保护写路径。
- **配置解析**: 自实现 INI 行解析器（`load_config_ini`），无第三方依赖，使用 `open()/read()` 系统调用（满足"不使用 FILE* 操作"要求）。

### 2.2 logger_storage.c — 离线存储引擎
- **文件命名**: `log-YYYYMMDD-HHMMSS.txt`
- **写入格式**: `[4字节小端 frame_len][entry 数据]`，支持逐帧解码/过滤。
- **轮转**: 写入前检查 `current_size + len > max_file_size`，超出则 `open_new_file()`。
- **总量控制**: `enforce_total_size()` 按 mtime 升序删除最旧文件，直到 ≤ `max_total_size`。
- **I/O**: 全程使用 `open()/write()/read()/close()` — **禁止 `fopen/fwrite`**。

### 2.3 logger_transport.c — UDP 传输层

```
发送侧 (send_fd)          查询服务侧 (query_fd, 独立线程)
─────────────────         ─────────────────────────────────
transport_send_log()      PKT_QUERY_LIST  → handle_query_list()
  → send_packet()            返回 "filename|size|ts\n" 列表
  → TransportHeader       PKT_QUERY_READ  → handle_query_read()
  → CRC32                    storage_read_file() → send_chunked()
  → 可选 AES 加密              stop-and-wait ARQ (seq/ACK/NACK)
```

**分块传输协议**:
```
Sender: [HDR seq=0 total=N] [payload_chunk_0]
Receiver: [ACK seq=0]
Sender: [HDR seq=1 total=N] [payload_chunk_1]
...
超时/NACK: 重传，最多 TRANSPORT_MAX_RETRY=3 次
```

### 2.4 logger_protection.c — 去重 / 自我保护

```
djb2_hash(module + ":" + message)
         │
         ▼  查 DedupEntry table[64]
    ┌────────────────────────────────────┐
    │ 未找到: 新建 entry, count=1, 放行  │
    │ 找到且 elapsed > window_ms:        │
    │   重置计数, 放行 (可能发 summary)  │
    │ 找到且 count > max_count:          │
    │   suppressing=true, 返回 allow=false│
    └────────────────────────────────────┘
```
窗口到期时自动输出：`[SUPPRESSED] "I2C:i2c send error" repeated 87 times in 5023ms`

### 2.5 logger_crypto.c — AES-256-CBC 加密

| 场景 | 行为 |
|------|------|
| 文件加密 | 每条 entry 独立加密，IV 随机生成，写入格式：`IV(16B) + ciphertext` |
| UDP 加密 | payload 加密，header 明文（含 CRC of 加密后数据） |
| 密钥管理 | `key_file` 首次生成（`/dev/urandom`），持久化为 mode 0600 文件 |

> **注意**: `logger_crypto.c` 中的 AES 实现为**占位 XOR 存根**，生产环境需替换为 [Tiny-AES-c](https://github.com/kokke/tiny-AES-c) 或 mbedTLS。

### 2.6 logger_crash.c — 被动崩溃捕获

```
crash_handler_install()
  → sigaction(SIGSEGV/SIGABRT/SIGBUS/SIGFPE/SIGILL/SIGTERM)
  → SA_SIGINFO | SA_RESETHAND

crash_signal_handler() (async-signal-safe):
  ① open(crash.log, O_WRONLY|O_CREAT|O_APPEND)
  ② write: 信号名、PID、fault address (ssa_write_* 函数，无 printf)
  ③ backtrace() + backtrace_symbols_fd(fd) → 写入调用栈
  ④ raise(signum) → 恢复默认行为 (core dump)
```

---

## 3. 文件结构

```
embedded-logger/
├── CMakeLists.txt              # 根构建脚本
├── config/
│   ├── config.ini              # 发送端/库配置
│   └── receiver.ini            # 接收端配置
├── include/
│   ├── logger.h                # 公共 API（含宏 LOG_INFO 等）
│   ├── logger_storage.h
│   ├── logger_transport.h
│   ├── logger_crypto.h
│   ├── logger_protection.h
│   └── logger_crash.h
├── src/
│   ├── core/
│   │   ├── logger_core.c       # 主编排器
│   │   ├── logger_storage.c    # 文件存储
│   │   └── logger_crash.c      # 信号处理
│   ├── transport/
│   │   └── logger_transport.c  # UDP + 分块 ARQ
│   ├── protection/
│   │   └── logger_protection.c # 去重保护
│   └── crypto/
│       └── logger_crypto.c     # AES-256-CBC
├── apps/
│   ├── sender/
│   │   ├── CMakeLists.txt
│   │   └── sender_main.c       # UDP 日志发送端
│   └── receiver/
│       ├── CMakeLists.txt
│       └── receiver_main.c     # UDP 日志接收端 (带颜色 + 级别过滤)
└── tests/
    ├── CMakeLists.txt
    └── test_logger.cpp         # GTest 单元测试
```

---

## 4. 构建与运行

```bash
# 克隆与初始化
git init
git add .
git commit -m "feat: initial embedded-logger framework"




# 配置构建 (Release)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 编译
cmake --build build --parallel

# 运行单元测试
cd build && ctest --output-on-failure

# 运行接收端 (窗口1)
./build/bin/log_receiver config/receiver.ini

# 运行发送端 (窗口2)
./build/bin/log_sender config/config.ini
```

---

## 5. 扩展点

| 扩展需求 | 扩展位置 |
|----------|----------|
| 替换 AES 实现 | `src/crypto/logger_crypto.c` — 替换 `aes256_cbc_*_stub` |
| 增加 JSON 配置格式 | `logger_core.c` — 新增 `load_config_json()` |
| 增加 syslog 后端 | 新增 `src/output/logger_syslog.c`，在 `logger_write()` 末尾调用 |
| ZSTD 压缩存储 | `logger_storage.c` — `storage_write()` 前调用压缩函数 |
| 多接收端组播 | `logger_transport.c` — `send_packet()` 使用 `sendmsg()` + IP_MULTICAST |
| MQTT 传输后端 | 新增 `src/transport/logger_mqtt.c` |
