package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"YASS-Backend/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

const (
	DefaultRateLimit int64 = 250 // 默认速率限制为250 Mbps
)

// 定义全局的缓冲池
var bufferPool = sync.Pool{
	New: func() interface{} {
		// 每个缓冲区大小为 4MB
		return make([]byte, 4*1024*1024) // 4MB
	},
}

var (
	mount_dir string
	port      string
	rateLimit int64

	// 新增安全配置
	aesKey     []byte
	hmacSecret []byte

	// 全局日志实例
	log *logger.Logger

	// 请求频率限制配置
	requestsPerSecond rate.Limit
	burstSize         int
	cleanupInterval   time.Duration
	expireDuration    time.Duration

	// 签名有效时间配置（防止重放攻击）
	signatureValidityPeriod int64
)

// ---- START: 请求频率限制 ----

// 访问者结构体，为每个客户端保存速率限制器和最后访问时间
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// 全局映射，存储访问者的速率限制器
// 键是客户端的IP地址
var visitors = make(map[string]*visitor)
var visitorsMu sync.Mutex

// 请求频率限制中间件，基于IP地址提供速率限制
func requestLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		visitorsMu.Lock()
		v, exists := visitors[ip]
		if !exists {
			limiter := rate.NewLimiter(requestsPerSecond, burstSize)
			v = &visitor{limiter: limiter}
			visitors[ip] = v
		}
		// 更新访问者的最后访问时间
		v.lastSeen = time.Now()
		visitorsMu.Unlock()

		// 检查请求是否被允许，如果不允许则返回429状态码
		if !v.limiter.Allow() {
			c.AbortWithStatus(http.StatusTooManyRequests)
			if log != nil {
				log.Warnf("Too many requests from IP: %s", ip)
			}
			return
		}

		c.Next()
	}
}

// cleanupVisitors 在后台goroutine中运行，用于清理访问者映射中的旧条目
// 防止内存泄漏
func cleanupVisitors() {
	for {
		// 等待一段时间后进行下一次清理循环
		time.Sleep(cleanupInterval)

		visitorsMu.Lock()
		for ip, v := range visitors {
			// 如果访问者在过期时间内未被访问，则从映射中删除
			if time.Since(v.lastSeen) > expireDuration {
				delete(visitors, ip)
			}
		}
		visitorsMu.Unlock()
	}
}

// ---- END: 请求频率限制 ----

// 速率限制器 (用于带宽限制)
type rateLimiter struct {
	bytesPerSecond int64
	lastCheck      time.Time
	bytesSent      int64
	mu             sync.Mutex
}

func newRateLimiter(mbps int64) *rateLimiter {
	return &rateLimiter{
		bytesPerSecond: (mbps * 1000 * 1000) / 8, // 将 Mbps 转换为字节/秒
		lastCheck:      time.Now(),
	}
}

func (rl *rateLimiter) limit(n int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.bytesPerSecond <= 0 {
		return
	}

	rl.bytesSent += int64(n)
	now := time.Now()
	elapsed := now.Sub(rl.lastCheck).Seconds()

	if elapsed > 0 {
		allowedBytes := int64(elapsed * float64(rl.bytesPerSecond))
		if rl.bytesSent > allowedBytes {
			delay := time.Duration(float64(rl.bytesSent-allowedBytes) / float64(rl.bytesPerSecond) * float64(time.Second))
			time.Sleep(delay)
			rl.lastCheck = now
			rl.bytesSent = 0
		}
	}
}

// AES-GCM解密函数
func aesGcmDecrypt(encryptedHex string) (string, error) {
	if log != nil {
		log.Debugf("开始AES-GCM解密，加密数据长度: %d", len(encryptedHex))
	}

	// 将十六进制字符串转换为字节
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		if log != nil {
			log.Errorf("十六进制解码失败: %v", err)
		}
		return "", err
	}

	// 检查数据长度
	if len(encryptedData) < 12 { // nonce长度为12字节
		if log != nil {
			log.Error("加密数据长度无效: %d", len(encryptedData))
		}
		return "", fmt.Errorf("invalid encrypted data length")
	}

	// 提取nonce, ciphertext和tag
	nonce := encryptedData[:12]
	tagAndCiphertext := encryptedData[12:]

	// tag长度为16字节
	if len(tagAndCiphertext) < 16 {
		if log != nil {
			log.Error("密文和标签长度无效: %d", len(tagAndCiphertext))
		}
		return "", fmt.Errorf("invalid ciphertext and tag length")
	}

	ciphertext := tagAndCiphertext[:len(tagAndCiphertext)-16]
	tag := tagAndCiphertext[len(tagAndCiphertext)-16:]

	// 创建AES-GCM解密器
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		if log != nil {
			log.Errorf("创建AES密码失败: %v", err)
		}
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		if log != nil {
			log.Errorf("创建GCM失败: %v", err)
		}
		return "", err
	}

	// 解密数据
	plaintext, err := aesGcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		if log != nil {
			log.Errorf("解密失败: %v", err)
		}
		return "", err
	}

	if log != nil {
		log.Debug("AES-GCM解密成功")
	}
	return string(plaintext), nil
}

// HMAC-SHA256签名验证函数
func verifySignature(dir, userid, ts, signature string) bool {
	if log != nil {
		log.Debugf("开始验证签名 - 用户ID: %s, 时间戳: %s", userid, ts)
	}

	// 验证时间戳有效性，防止重放攻击
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		if log != nil {
			log.Warnf("时间戳格式无效 - 用户ID: %s, 时间戳: %s", userid, ts)
		}
		return false
	}

	// 检查时间戳是否在配置的签名有效期内
	now := time.Now().Unix()
	if now-timestamp > signatureValidityPeriod || timestamp-now > signatureValidityPeriod {
		if log != nil {
			log.Warnf("时间戳超出签名有效期 - 用户ID: %s, 时间戳: %s, 当前时间: %d, 有效期: %d秒", userid, ts, now, signatureValidityPeriod)
		}
		return false
	}

	// 先解密路径以获取原始路径用于签名验证
	decryptedDir, err := aesGcmDecrypt(dir)
	if err != nil {
		if log != nil {
			log.Errorf("路径解密失败，无法验证签名 - 用户ID: %s, 错误: %v", userid, err)
		}
		return false
	}

	// 构造用于签名的消息（使用解密后的路径）
	message := fmt.Sprintf("dir=%s&userid=%s&ts=%s", decryptedDir, userid, ts)

	// 创建HMAC-SHA256签名
	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write([]byte(message))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// 比较签名
	isValid := hmac.Equal([]byte(signature), []byte(expectedSignature))

	if isValid {
		if log != nil {
			log.Infof("签名验证成功 - 用户ID: %s", userid)
		}
	} else {
		if log != nil {
			log.Warnf("签名验证失败 - 用户ID: %s", userid)
			log.Debugf("用于签名的消息: %s", message)
			log.Debugf("期望签名: %s", expectedSignature)
			log.Debugf("实际签名: %s", signature)
		}
	}

	return isValid
}

// 处理 HTTP Range 请求，支持按需加载
func remote(c *gin.Context) {
	// 获取查询参数
	encryptedDir := c.Query("dir")
	userid := c.Query("userid")
	ts := c.Query("ts")
	signature := c.Query("signature")

	if log != nil {
		log.Infof("收到新的流请求 - 客户端IP: %s, 用户ID: %s, 时间戳: %s, 加密路径长度: %d, 签名长度: %d",
			c.ClientIP(),
			userid,
			ts,
			len(encryptedDir),
			len(signature))
	}

	// 验证签名（在解密路径之前）
	if !verifySignature(encryptedDir, userid, ts, signature) {
		if log != nil {
			log.Warnf("签名验证失败 - 用户ID: %s, 客户端IP: %s", userid, c.ClientIP())
		}
		c.AbortWithStatus(403)
		return
	}

	// 解密路径（verifySignature函数中已经解密了路径，但为了代码清晰，我们再解密一次）
	decryptedDir, err := aesGcmDecrypt(encryptedDir)
	if err != nil {
		if log != nil {
			log.Errorf("路径解密失败 - 用户ID: %s, 客户端IP: %s, 错误: %v", userid, c.ClientIP(), err)
		}
		c.AbortWithStatus(403)
		return
	}

	// 构造完整文件路径
	local_dir := mount_dir + decryptedDir
	if log != nil {
		log.Infof("尝试访问文件 - 用户ID: %s, 客户端IP: %s, 路径: %s", userid, c.ClientIP(), local_dir)
	}

	file, err := os.Open(local_dir)
	if err != nil {
		if log != nil {
			log.Errorf("文件打开失败 - 用户ID: %s, 客户端IP: %s, 路径: %s, 错误: %v", userid, c.ClientIP(), local_dir, err)
		}
		c.AbortWithStatus(403)
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		if log != nil {
			log.Errorf("获取文件信息失败 - 用户ID: %s, 客户端IP: %s, 路径: %s, 错误: %v", userid, c.ClientIP(), local_dir, err)
		}
		c.AbortWithStatus(500)
		return
	}
	fileSize := fileInfo.Size()
	if log != nil {
		log.Infof("文件信息获取成功 - 用户ID: %s, 客户端IP: %s, 路径: %s, 大小: %d bytes", userid, c.ClientIP(), local_dir, fileSize)
	}

	// 解析 Range 请求头
	rangeHeader := c.GetHeader("Range")
	if rangeHeader == "" {
		// 如果没有 Range 头，返回整个文件
		if log != nil {
			log.Infof("无Range请求头，返回整个文件 - 用户ID: %s, 客户端IP: %s", userid, c.ClientIP())
		}
		c.Writer.Header().Set("Content-Type", "video/mp4")
		c.Writer.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		c.Status(http.StatusOK)

		// 分片传输整个文件
		streamFile(file, c, 0, fileSize-1)
		return
	}

	// Range 请求的格式：bytes=起始位置-结束位置
	ranges := strings.Split(rangeHeader, "=")
	if len(ranges) != 2 || ranges[0] != "bytes" {
		if log != nil {
			log.Warnf("Range请求头格式无效 - 用户ID: %s, 客户端IP: %s, Range头: %s", userid, c.ClientIP(), rangeHeader)
		}
		c.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	rangeParts := strings.Split(ranges[1], "-")

	start, err := strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil || start < 0 || start >= fileSize {
		if log != nil {
			log.Warnf("Range起始位置无效 - 用户ID: %s, 客户端IP: %s, 起始位置: %s, 文件大小: %d", userid, c.ClientIP(), rangeParts[0], fileSize)
		}
		c.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	var end int64
	if rangeParts[1] != "" {
		end, err = strconv.ParseInt(rangeParts[1], 10, 64)
		if err != nil || end >= fileSize || end < start {
			if log != nil {
				log.Warnf("Range结束位置无效 - 用户ID: %s, 客户端IP: %s, 结束位置: %s, 起始位置: %d, 文件大小: %d", userid, c.ClientIP(), rangeParts[1], start, fileSize)
			}
			c.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
			return
		}
	} else {
		end = fileSize - 1
	}

	// 设置响应头信息
	contentLength := end - start + 1
	if log != nil {
		log.Infof("处理Range请求 - 用户ID: %s, 客户端IP: %s, 范围: %d-%d, 长度: %d", userid, c.ClientIP(), start, end, contentLength)
	}
	c.Writer.Header().Set("Content-Type", "video/mp4")
	c.Writer.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	c.Writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	c.Status(http.StatusPartialContent)

	// 分片传输文件的指定范围
	streamFile(file, c, start, end)
}

// 分片传输文件的指定部分
func streamFile(file *os.File, c *gin.Context, start, end int64) {
	if log != nil {
		log.Infof("开始流式传输文件 - 客户端IP: %s, 范围: %d-%d", c.ClientIP(), start, end)
	}

	// 移动文件指针到指定位置
	_, err := file.Seek(start, 0)
	if err != nil {
		if log != nil {
			log.Errorf("文件指针定位失败 - 客户端IP: %s, 错误: %v", c.ClientIP(), err)
		}
		c.AbortWithStatus(500)
		return
	}

	// 使用缓冲区按块读取并传输
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		// 修复：正确处理从缓冲池获取的值
		buffer := bufferPool.Get().([]byte)
		defer bufferPool.Put(buffer)

		limiter := newRateLimiter(rateLimit)
		totalBytes := end - start + 1
		bytesSent := int64(0)

		if log != nil {
			log.Debugf("开始传输数据 - 客户端IP: %s, 总字节数: %d", c.ClientIP(), totalBytes)
		}

		for totalBytes > 0 {
			readSize := int64(len(buffer))
			if totalBytes < readSize {
				readSize = totalBytes
			}

			n, err := file.Read(buffer[:readSize])
			if err != nil && err != io.EOF {
				if log != nil {
					log.Errorf("文件读取错误 - 客户端IP: %s, 错误: %v", c.ClientIP(), err)
				}
				c.AbortWithStatus(500)
				return
			}

			if n == 0 {
				break
			}

			limiter.limit(n) // 应用速率限制

			_, writeErr := c.Writer.Write(buffer[:n])
			if writeErr != nil {
				// 如果客户端断开连接
				if log != nil {
					log.Warnf("客户端连接断开 - 客户端IP: %s, 已发送字节: %d, 错误: %v", c.ClientIP(), bytesSent, writeErr)
				}
				return
			}

			c.Writer.Flush() // 刷新数据
			totalBytes -= int64(n)
			bytesSent += int64(n)
		}

		if log != nil {
			log.Infof("文件传输完成 - 客户端IP: %s, 总发送字节: %d", c.ClientIP(), bytesSent)
		}
	}()

	wg.Wait()
}

// 定义中间件处理跨域请求
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

// 自定义Gin日志中间件，使用logrus记录日志
func ginLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 开始时间
		startTime := time.Now()

		// 处理请求
		c.Next()

		// 结束时间
		endTime := time.Now()

		// 执行时间
		latencyTime := endTime.Sub(startTime)

		// 请求方式
		reqMethod := c.Request.Method

		// 请求路由
		reqUri := c.Request.RequestURI

		// 状态码
		statusCode := c.Writer.Status()

		// 请求IP
		clientIP := c.ClientIP()

		// 从查询参数中获取userid
		userid := c.Query("userid")
		if userid == "" {
			userid = "unknown"
		}

		// 日志格式
		if log != nil {
			log.Infof("[GIN] %16v | %3d | %13v | %15s | %8s | %s | %s",
				endTime.Format("2006-01-02 15:04:05.000"),
				statusCode,
				latencyTime,
				clientIP,
				userid,
				reqMethod,
				reqUri,
			)
		}
	}
}

func main() {
	// 创建一个临时的日志记录器用于初始化阶段
	tempLogger := logrus.New()
	tempLogger.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})

	// 读取配置文件
	args := os.Args[1:]
	if len(args) == 0 {
		tempLogger.Error("请提供配置文件作为参数")
		return
	}
	configFile := args[0]

	tempLogger.Infof("正在加载配置文件: %s", configFile)
	viper.SetConfigType("yaml")
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		tempLogger.Errorf("读取配置文件错误: %v", err)
		return
	}

	// 从配置文件中读取参数
	mount_dir = viper.GetString("mount.dir")
	port = viper.GetString("server.port")

	tempLogger.Infof("配置已加载 - 挂载目录: %s, 端口: %s", mount_dir, port)

	// 读取新的安全配置
	aesKeyHex := viper.GetString("security.aes_key")
	hmacSecretHex := viper.GetString("security.hmac_secret_key")

	// 将十六进制字符串转换为字节
	var err error
	aesKey, err = hex.DecodeString(aesKeyHex)
	if err != nil {
		tempLogger.Errorf("AES密钥解码错误: %v", err)
		return
	}

	hmacSecret, err = hex.DecodeString(hmacSecretHex)
	if err != nil {
		tempLogger.Errorf("HMAC密钥解码错误: %v", err)
		return
	}

	tempLogger.Info("安全配置已加载")

	// 读取速率限制，如果未设置则使用默认值
	if !viper.IsSet("server.rate_limit") {
		rateLimit = DefaultRateLimit
	} else {
		rateLimit = viper.GetInt64("server.rate_limit")
	}

	tempLogger.Infof("速率限制设置为: %d Mbps", rateLimit)

	// 读取请求频率限制配置
	if viper.IsSet("server.request_limit") {
		requestsPerSecond = rate.Limit(viper.GetFloat64("server.request_limit.requests_per_second"))
		burstSize = viper.GetInt("server.request_limit.burst_size")
		cleanupInterval = time.Duration(viper.GetInt("server.request_limit.cleanup_interval")) * time.Minute
		expireDuration = time.Duration(viper.GetInt("server.request_limit.expire_duration")) * time.Minute
	} else {
		// 默认值
		requestsPerSecond = 2
		burstSize = 10
		cleanupInterval = 10 * time.Minute
		expireDuration = 15 * time.Minute
	}

	tempLogger.Infof("请求频率限制配置 - 每秒请求数: %f, 突发大小: %d, 清理间隔: %v, 过期时间: %v",
		float64(requestsPerSecond), burstSize, cleanupInterval, expireDuration)

	// 读取签名有效时间配置（防止重放攻击），默认值为300秒（5分钟）
	if !viper.IsSet("security.signature_validity_period") {
		signatureValidityPeriod = 300
	} else {
		signatureValidityPeriod = viper.GetInt64("security.signature_validity_period")
	}

	tempLogger.Infof("签名有效期设置为: %d 秒", signatureValidityPeriod)

	// 初始化日志系统
	logConfig := logger.Config{
		Level:      viper.GetString("log.level"),
		File:       viper.GetString("log.file"),
		MaxSize:    viper.GetInt("log.max_size"),
		MaxBackups: viper.GetInt("log.max_backups"),
		MaxAge:     viper.GetInt("log.max_age"),
		Compress:   viper.GetBool("log.compress"),
	}

	log, err = logger.New(logConfig)
	if err != nil {
		tempLogger.Errorf("日志系统初始化失败: %v", err)
		return
	}

	log.Info("日志系统初始化完成")

	// 启动后台goroutine以清理旧的访问者记录
	go cleanupVisitors()

	// 初始化 Gin 引擎
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// 使用自定义的日志格式
	r.Use(ginLogger())
	r.Use(gin.Recovery())

	// 默认信任所有代理。这是为了在反向代理（如Nginx）环境下获取正确的
	// 客户端IP地址。
	r.SetTrustedProxies(nil)

	// 添加跨域中间件
	r.Use(corsMiddleware())

	// 将请求频率限制中间件添加到所有路由中。
	r.Use(requestLimitMiddleware())

	// 设置路由和文件流传输处理
	r.GET("/stream", remote)

	// 添加 NoRoute 处理器，处理所有未定义的路由
	r.NoRoute(func(c *gin.Context) {
		log.Warnf("访问了未定义的路由: %s", c.Request.URL.Path)
		c.AbortWithStatus(403)
	})

	log.Infof("服务启动中，监听端口: %s", port)
	// 启动服务，监听指定端口
	r.Run(":" + port)
}
