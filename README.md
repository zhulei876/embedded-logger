# embedded-logger

嵌入式 Linux C 日志库，支持离线存储、UDP 传输、AES-256 加密、去重保护与崩溃捕获。

## 特性

| 特性 | 说明 |
|------|------|
| **8级日志** | EMERG / ALERT / CRIT / ERR / WARNING / NOTICE / INFO / DEBUG |
| **离线存储** | `log-YYYYMMDD-HHMMSS.txt`，自动轮转，总量限制自动删旧 |
| **主动调用** | `LOG_INFO("MODULE", "fmt", ...)` 宏，线程安全 |
| **被动捕获** | SIGSEGV/SIGABRT/SIGBUS 信号处理，async-signal-safe 写入崩溃日志 |
| **UDP 传输** | 实时流发送 + 分块 ARQ（CRC32 + stop-and-wait 重传） |
| **查询协议** | loopback UDP：列举文件、按文件名读取、按级别过滤 |
| **AES-256-CBC** | 文件加密 + 传输加密，密钥自动生成并持久化 |
| **去重保护** | djb2 哈希 + 时间窗口抑制，防止 I2C 等模块日志洪泛 |
| **配置解耦** | `config.ini` 配置全部参数，无硬编码 |
| **库打包** | 静态库 `liblogger.a` + 可选动态库 `liblogger.so` |

## 快速开始

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
cd build && ctest --output-on-failure
```

接收端：
```bash
./build/bin/log_receiver config/receiver.ini
```

发送端：
```bash
./build/bin/log_sender config/config.ini
```

## 日志格式

```
[2025-08-25 14:30:00] [INFO] [PID:1234] [SD_CARD] SD card mount success
```

## 使用库

```c
#include "logger.h"

logger_init("config/config.ini");
logger_install_crash_handler();

LOG_INFO("SD_CARD", "SD card mount success");
LOG_ERR("I2C_BUS", "Transfer failed, errno=%d", errno);

logger_destroy();
```

详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
