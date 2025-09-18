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

## 如何配置

#### 1. 下载最新 Release

下载到你的运行目录下即可，无需解压。

#### 2. 配置 `config.yaml`

```yaml
# 目录头配置
Mount: 
  dir: "/mnt"

# 服务器配置
Server:
  port: "12180"
  rateLimit: 100 # Mbps, default 250

# 安全配置
Security:
  # AES密钥：必须是32位十六进制字符串 (16字节)
  aes_key: "a1b2c3d4e5f6789012345678901234ab"
  # HMAC密钥：有效的十六进制字符串
  hmac_secret_key: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
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