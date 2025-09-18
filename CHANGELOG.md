# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-09-18

### Added
- AES-GCM加密算法支持，用于路径加密
- HMAC-SHA256签名验证，增强安全性
- 自定义日志格式，统一时间戳和分隔符
- 详细的请求参数日志记录，便于监控和调试
- 完善的.gitignore文件，优化版本控制忽略规则
- CHANGELOG.md文件，记录项目变更历史

### Changed
- 鉴权机制从简单的MD5哈希改为AES-GCM加密+HMAC-SHA256签名
- 配置文件结构更新，支持新的安全配置项
- 日志输出格式统一，使用一致的时间格式和分隔符
- README文档更新，反映新的配置要求

### Fixed
- 签名验证函数逻辑错误，确保使用正确的路径进行签名验证
- 编译错误，移除了未使用的变量
- 日志格式不一致问题，统一了Gin框架和自定义日志的格式

### Security
- 增强了安全性，使用现代加密算法替代简单的哈希验证
- 添加了详细的日志记录，便于安全审计和问题排查

## [1.0.0] - 2025-09-18

### Added
- 初始版本发布
- 基于Go语言的视频流分离推送解决方案
- 支持分片传输和并发缓存池
- 基本的MD5哈希鉴权机制
- YAML配置文件支持