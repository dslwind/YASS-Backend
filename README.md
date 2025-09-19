# YASS-Backend
**Yet Another Stream Splitter (Generally for EMBY)**

![Main Branch Build CI](https://github.com/FacMata/YASS-Backend/actions/workflows/main.yml/badge.svg)    ![Dev Branch Build CI](https://github.com/FacMata/YASS-Backend/actions/workflows/dev.yml/badge.svg)

## 这是什么

### YASS

一个基于 [MisakaFxxk](https://github.com/MisakaFxxk) 的 [Go_stream](https://github.com/MisakaFxxk/Go_stream) 项目改进而来的，EMBY 视频流分离推送解决方案的程序组。

在 [MisakaFxxk](https://github.com/MisakaFxxk) 没有更新的前提下，它与 YASS-Frontend 可以作为原程序的后继者。

### YASS Backend

YASS 项目的后端程序。其完成的工作是从本地目录找到前端请求的实际文件，以视频流的形式传递给客户端。

本程序在 [Go_stream](https://github.com/MisakaFxxk/Go_stream) 的基础上利用更多 Go 的特性，比如分片传输、并发缓存池、连接回收等，播放效率相比原版有一定提升。

**目前** 可以搭配原版前端使用，也可以搭配 [YASS-Frontend](https://github.com/FacMata/YASS-Frontend) 使用。

## 功能特性

- 分片传输：支持大文件高效流式读取
- 并发缓存池：提升多用户访问性能
- 连接回收机制：减少资源消耗
- 可配置的挂载目录与速率限制
- AES-GCM加密路径和HMAC-SHA256签名验证，增强安全性
- 请求频率限制，防止滥用
- 详细的日志记录系统，支持文件输出、轮转和压缩
- 签名有效期验证，防止重放攻击

## 如何配置

#### 1. 下载最新 Release

下载到你的运行目录下即可，无需解压。

#### 2. 配置 `config.yaml`

```yaml
# YASS-Backend 配置文件示例

# 目录头配置
mount: 
  dir: "/mnt/media"  # 挂载目录前缀

# 服务器配置
server:
  port: "12180"      # 服务监听端口
  rate_limit: 100    # 带宽限制 (Mbps)
  # 请求频率限制配置
  request_limit:
    requests_per_second: 2    # 每秒请求数限制
    burst_size: 10            # 突发请求大小
    cleanup_interval: 10      # 清理间隔（分钟）
    expire_duration: 15       # 过期时间（分钟）

# 安全配置
security:
  # AES密钥：必须是32位十六进制字符串 (16字节)
  # 可以使用以下命令生成：openssl rand -hex 16
  aes_key: "a1b2c3d4e5f6789012345678901234ab"
  
  # HMAC密钥：有效的十六进制字符串
  # 可以使用以下命令生成：openssl rand -hex 32
  hmac_secret_key: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
  
  # 签名有效时间（秒）：防止重放攻击的时间窗口，默认300秒（5分钟）
  signature_validity_period: 300

# 日志配置
log:
  level: "info"           # 日志级别: trace, debug, info, warn, error, fatal, panic
  file: "logs/app.log"    # 日志文件路径
  max_size: 10            # 每个日志文件的最大大小(MB)
  max_backups: 5          # 保留的旧日志文件最大个数
  max_age: 30             # 保留旧日志文件的最大天数
  compress: true          # 是否压缩旧日志文件
```

#### 3. 运行程序

```shell
# sudo chmod +x <filename>
# ./<filename> config.yaml
```

持久化运行推荐使用 `SystemD System Service` 或者 `screen` 。

## 寻求交流

Email: [contact@facmata.net](mailto://contact@facmata.net)

Telegram Group: [YASS Talking](https://t.me/YASS_Talking)