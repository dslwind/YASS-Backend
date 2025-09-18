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

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

// 自定义日志格式化函数
func logFormat(params gin.LogFormatterParams) string {
	return fmt.Sprintf("[%s] | %s | %d | %s | %s | %s | %s\n",
		params.TimeStamp.Format("2006-01-02 15:04:05"),
		params.ClientIP,
		params.StatusCode,
		params.Latency,
		params.Method,
		params.Path,
		params.ErrorMessage,
	)
}

// Add this after the imports
const (
	DefaultRateLimit int64 = 250 // Default rate limit in Mbps
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
)

// ---- START: New code for Request Frequency Limiting ----

// visitor struct holds the rate limiter and last seen time for each client.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Global map to store visitors' rate limiters.
// The key is the client's IP address.
var visitors = make(map[string]*visitor)
var visitorsMu sync.Mutex

// requestLimitMiddleware provides rate limiting based on IP address.
func requestLimitMiddleware() gin.HandlerFunc {
	// These values can be moved to the config file if more flexibility is needed.
	// r: requests per second.
	// b: burst size.
	// Here we allow 2 requests per second with a burst of 10.
	// This is suitable for streaming where a client might make several quick requests
	// at the beginning, but prevents sustained high-frequency requests.
	r := rate.Limit(2)
	b := 10

	return func(c *gin.Context) {
		ip := c.ClientIP()

		visitorsMu.Lock()
		v, exists := visitors[ip]
		if !exists {
			limiter := rate.NewLimiter(r, b)
			v = &visitor{limiter: limiter}
			visitors[ip] = v
		}
		// Update the last seen time for the visitor on every request.
		v.lastSeen = time.Now()
		visitorsMu.Unlock()

		// Check if the request is allowed. If not, abort with a 429 status.
		if !v.limiter.Allow() {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		c.Next()
	}
}

// cleanupVisitors runs in a background goroutine to remove old entries
// from the visitors map, preventing a memory leak.
func cleanupVisitors() {
	for {
		// Wait for a while before the next cleanup cycle.
		time.Sleep(10 * time.Minute)

		visitorsMu.Lock()
		for ip, v := range visitors {
			// If a visitor hasn't been seen for 15 minutes, remove them from the map.
			if time.Since(v.lastSeen) > 15*time.Minute {
				delete(visitors, ip)
			}
		}
		visitorsMu.Unlock()
	}
}

// ---- END: New code for Request Frequency Limiting ----

// 速率限制器 (This is for bandwidth limiting)
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
	fmt.Printf("[%s] 开始AES-GCM解密，加密数据长度: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(encryptedHex))

	// 将十六进制字符串转换为字节
	encryptedData, err := hex.DecodeString(encryptedHex)
	if err != nil {
		fmt.Printf("[%s] 十六进制解码失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return "", err
	}

	// 检查数据长度
	if len(encryptedData) < 12 { // nonce长度为12字节
		fmt.Printf("[%s] 加密数据长度无效: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(encryptedData))
		return "", fmt.Errorf("invalid encrypted data length")
	}

	// 提取nonce, ciphertext和tag
	nonce := encryptedData[:12]
	tagAndCiphertext := encryptedData[12:]

	// tag长度为16字节
	if len(tagAndCiphertext) < 16 {
		fmt.Printf("[%s] 密文和标签长度无效: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(tagAndCiphertext))
		return "", fmt.Errorf("invalid ciphertext and tag length")
	}

	ciphertext := tagAndCiphertext[:len(tagAndCiphertext)-16]
	tag := tagAndCiphertext[len(tagAndCiphertext)-16:]

	// 创建AES-GCM解密器
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Printf("[%s] 创建AES密码失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return "", err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("[%s] 创建GCM失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return "", err
	}

	// 解密数据
	plaintext, err := aesGcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		fmt.Printf("[%s] 解密失败: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return "", err
	}

	fmt.Printf("[%s] AES-GCM解密成功\n", time.Now().Format("2006-01-02 15:04:05"))
	return string(plaintext), nil
}

// HMAC-SHA256签名验证函数
func verifySignature(dir, userid, ts, signature string) bool {
	fmt.Printf("[%s] 开始验证签名 - 用户ID: %s, 时间戳: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid, ts)
	
	// 先解密路径以获取原始路径用于签名验证
	decryptedDir, err := aesGcmDecrypt(dir)
	if err != nil {
		fmt.Printf("[%s] 路径解密失败，无法验证签名 - 用户ID: %s, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), userid, err)
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
		fmt.Printf("[%s] 签名验证成功 - 用户ID: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid)
	} else {
		fmt.Printf("[%s] 签名验证失败 - 用户ID: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid)
		fmt.Printf("[%s] 用于签名的消息: %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
		fmt.Printf("[%s] 期望签名: %s\n", time.Now().Format("2006-01-02 15:04:05"), expectedSignature)
		fmt.Printf("[%s] 实际签名: %s\n", time.Now().Format("2006-01-02 15:04:05"), signature)
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

	fmt.Printf("[%s] 收到新的流请求 - 客户端IP: %s, 用户ID: %s, 时间戳: %s, 加密路径长度: %d, 签名长度: %d\n",
		time.Now().Format("2006-01-02 15:04:05"),
		c.ClientIP(),
		userid,
		ts,
		len(encryptedDir),
		len(signature))

	// 验证签名（在解密路径之前）
	if !verifySignature(encryptedDir, userid, ts, signature) {
		fmt.Printf("[%s] 签名验证失败 - 用户ID: %s, 客户端IP: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP())
		c.AbortWithStatus(403)
		return
	}

	// 解密路径（verifySignature函数中已经解密了路径，但为了代码清晰，我们再解密一次）
	decryptedDir, err := aesGcmDecrypt(encryptedDir)
	if err != nil {
		fmt.Printf("[%s] 路径解密失败 - 用户ID: %s, 客户端IP: %s, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), err)
		c.AbortWithStatus(403)
		return
	}

	// 构造完整文件路径
	local_dir := mount_dir + decryptedDir
	fmt.Printf("[%s] 尝试访问文件 - 用户ID: %s, 客户端IP: %s, 路径: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), local_dir)

	file, err := os.Open(local_dir)
	if err != nil {
		fmt.Printf("[%s] 文件打开失败 - 用户ID: %s, 客户端IP: %s, 路径: %s, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), local_dir, err)
		c.AbortWithStatus(403)
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Printf("[%s] 获取文件信息失败 - 用户ID: %s, 客户端IP: %s, 路径: %s, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), local_dir, err)
		c.AbortWithStatus(500)
		return
	}
	fileSize := fileInfo.Size()
	fmt.Printf("[%s] 文件信息获取成功 - 用户ID: %s, 客户端IP: %s, 路径: %s, 大小: %d bytes\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), local_dir, fileSize)

	// 解析 Range 请求头
	rangeHeader := c.GetHeader("Range")
	if rangeHeader == "" {
		// 如果没有 Range 头，返回整个文件
		fmt.Printf("[%s] 无Range请求头，返回整个文件 - 用户ID: %s, 客户端IP: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP())
		c.Writer.Header().Set("Content-Type", "video/mp4")
		c.Writer.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		c.Status(http.StatusOK)

		// 分片传输整个文件
		streamFile(file, c, 0, fileSize-1)
		return
	}

	// Range 请求的格式: bytes=START-END
	ranges := strings.Split(rangeHeader, "=")
	if len(ranges) != 2 || ranges[0] != "bytes" {
		fmt.Printf("[%s] Range请求头格式无效 - 用户ID: %s, 客户端IP: %s, Range头: %s\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), rangeHeader)
		c.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	rangeParts := strings.Split(ranges[1], "-")

	start, err := strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil || start < 0 || start >= fileSize {
		fmt.Printf("[%s] Range起始位置无效 - 用户ID: %s, 客户端IP: %s, 起始位置: %s, 文件大小: %d\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), rangeParts[0], fileSize)
		c.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	var end int64
	if rangeParts[1] != "" {
		end, err = strconv.ParseInt(rangeParts[1], 10, 64)
		if err != nil || end >= fileSize || end < start {
			fmt.Printf("[%s] Range结束位置无效 - 用户ID: %s, 客户端IP: %s, 结束位置: %s, 起始位置: %d, 文件大小: %d\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), rangeParts[1], start, fileSize)
			c.AbortWithStatus(http.StatusRequestedRangeNotSatisfiable)
			return
		}
	} else {
		end = fileSize - 1
	}

	// 设置响应头信息
	contentLength := end - start + 1
	fmt.Printf("[%s] 处理Range请求 - 用户ID: %s, 客户端IP: %s, 范围: %d-%d, 长度: %d\n", time.Now().Format("2006-01-02 15:04:05"), userid, c.ClientIP(), start, end, contentLength)
	c.Writer.Header().Set("Content-Type", "video/mp4")
	c.Writer.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	c.Writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
	c.Status(http.StatusPartialContent)

	// 分片传输文件的指定范围
	streamFile(file, c, start, end)
}

// 分片传输文件的指定部分
func streamFile(file *os.File, c *gin.Context, start, end int64) {
	fmt.Printf("[%s] 开始流式传输文件 - 客户端IP: %s, 范围: %d-%d\n", time.Now().Format("2006-01-02 15:04:05"), c.ClientIP(), start, end)

	// 移动文件指针到指定位置
	_, err := file.Seek(start, 0)
	if err != nil {
		fmt.Printf("[%s] 文件指针定位失败 - 客户端IP: %s, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), c.ClientIP(), err)
		c.AbortWithStatus(500)
		return
	}

	// 使用缓冲区按块读取并传输
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		buffer := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(buffer)

		limiter := newRateLimiter(rateLimit)
		totalBytes := end - start + 1
		bytesSent := int64(0)

		fmt.Printf("[%s] 开始传输数据 - 客户端IP: %s, 总字节数: %d\n", time.Now().Format("2006-01-02 15:04:05"), c.ClientIP(), totalBytes)

		for totalBytes > 0 {
			readSize := int64(len(*buffer))
			if totalBytes < readSize {
				readSize = totalBytes
			}

			n, err := file.Read((*buffer)[:readSize])
			if err != nil && err != io.EOF {
				fmt.Printf("[%s] 文件读取错误 - 客户端IP: %s, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), c.ClientIP(), err)
				c.AbortWithStatus(500)
				return
			}

			if n == 0 {
				break
			}

			limiter.limit(n) // 应用速率限制

			_, writeErr := c.Writer.Write((*buffer)[:n])
			if writeErr != nil {
				// 如果客户端断开连接
				fmt.Printf("[%s] 客户端连接断开 - 客户端IP: %s, 已发送字节: %d, 错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), c.ClientIP(), bytesSent, writeErr)
				return
			}

			c.Writer.Flush() // 刷新数据
			totalBytes -= int64(n)
			bytesSent += int64(n)
		}

		fmt.Printf("[%s] 文件传输完成 - 客户端IP: %s, 总发送字节: %d\n", time.Now().Format("2006-01-02 15:04:05"), c.ClientIP(), bytesSent)
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

func main() {
	// 读取配置文件
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("[", time.Now().Format("2006-01-02 15:04:05"), "] 请提供配置文件作为参数")
		return
	}
	configFile := args[0]

	fmt.Printf("[%s] 正在加载配置文件: %s\n", time.Now().Format("2006-01-02 15:04:05"), configFile)
	viper.SetConfigType("yaml")
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("[%s] 读取配置文件错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		fmt.Println("Error reading config file:", err)
		return
	}

	// 从配置文件中读取参数
	mount_dir = viper.GetString("mount.dir")
	port = viper.GetString("server.port")

	fmt.Printf("[%s] 配置已加载 - 挂载目录: %s, 端口: %s\n", time.Now().Format("2006-01-02 15:04:05"), mount_dir, port)

	// 读取新的安全配置
	aesKeyHex := viper.GetString("security.aes_key")
	hmacSecretHex := viper.GetString("security.hmac_secret_key")

	// 将十六进制字符串转换为字节
	var err error
	aesKey, err = hex.DecodeString(aesKeyHex)
	if err != nil {
		fmt.Printf("[%s] AES密钥解码错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		fmt.Println("Error decoding AES key:", err)
		return
	}

	hmacSecret, err = hex.DecodeString(hmacSecretHex)
	if err != nil {
		fmt.Printf("[%s] HMAC密钥解码错误: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		fmt.Println("Error decoding HMAC secret:", err)
		return
	}

	fmt.Printf("[%s] 安全配置已加载\n", time.Now().Format("2006-01-02 15:04:05"))

	// 读取速率限制，如果未设置则使用默认值
	if !viper.IsSet("server.rateLimit") {
		rateLimit = DefaultRateLimit
	} else {
		rateLimit = viper.GetInt64("server.rateLimit")
	}

	fmt.Printf("[%s] 速率限制设置为: %d Mbps\n", time.Now().Format("2006-01-02 15:04:05"), rateLimit)

	// Start the background goroutine to clean up old visitors.
	go cleanupVisitors()

	// 初始化 Gin 引擎
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	// 使用自定义的日志格式
	r.Use(gin.LoggerWithFormatter(logFormat))
	r.Use(gin.Recovery())

	// Trust all proxies by default. This is needed to get the correct
	// client IP when running behind a reverse proxy like Nginx.
	r.SetTrustedProxies(nil)

	// 添加跨域中间件
	r.Use(corsMiddleware())

	// Add the request rate limiting middleware to all routes.
	r.Use(requestLimitMiddleware())

	// 设置路由和文件流传输处理
	r.GET("/stream", remote)

	// 添加 NoRoute 处理器，处理所有未定义的路由
	r.NoRoute(func(c *gin.Context) {
		fmt.Printf("[%s] 访问了未定义的路由: %s\n", time.Now().Format("2006-01-02 15:04:05"), c.Request.URL.Path)
		c.AbortWithStatus(403)
	})

	fmt.Printf("[%s] 服务启动中，监听端口: %s\n", time.Now().Format("2006-01-02 15:04:05"), port)
	// 启动服务，监听指定端口
	r.Run(":" + port)
}
