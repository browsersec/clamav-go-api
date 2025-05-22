package main

import (
	//	"bytes"
	//	"encoding/json"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/net/context"
)

// Configuration struct
type Config struct {
	AppPort           string
	AppFormKey        string
	AppMaxFileSize    int64
	AppMaxFilesNumber int
	ClamdIP           string
	ClamdPort         string
	ClamdTimeout      time.Duration
	NodeEnv           string
	MorganLogFormat   string
	RedisURL          string
	JobExpiration     int
}

// Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
}

type ScanResult struct {
	Name       string   `json:"name"`
	IsInfected bool     `json:"is_infected"`
	Viruses    []string `json:"viruses"`
}

type ScanResponse struct {
	Result []ScanResult `json:"result"`
}

type VersionResponse struct {
	Version string `json:"version"`
}

type DBSignaturesResponse struct {
	LocalClamAVDBSignature  string `json:"local_clamav_db_signature"`
	RemoteClamAVDBSignature string `json:"remote_clamav_db_signature"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Job status constants
const (
	JobStatusPending  = "pending"
	JobStatusComplete = "complete"
	JobStatusFailed   = "failed"
)

// Job related structures
type Job struct {
	ID        string      `json:"id"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	Result    interface{} `json:"result,omitempty"`
}

type JobResponse struct {
	JobID string `json:"job_id"`
}

type JobStatusResponse struct {
	Job *Job `json:"job"`
}

// Redis message structures
type ScanMessage struct {
	JobID     string   `json:"job_id"`
	FileData  [][]byte `json:"file_data"`
	FileNames []string `json:"file_names"`
}

// ClamAV client
type ClamAVClient struct {
	host    string
	port    string
	timeout time.Duration
}

func NewClamAVClient(host, port string, timeout time.Duration) *ClamAVClient {
	return &ClamAVClient{
		host:    host,
		port:    port,
		timeout: timeout,
	}
}

func (c *ClamAVClient) connect() (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.host, c.port), c.timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *ClamAVClient) ScanStream(data []byte) (*ScanResult, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClamAV: %v", err)
	}
	defer conn.Close()

	// Send INSTREAM command
	_, err = conn.Write([]byte("zINSTREAM\x00"))
	if err != nil {
		return nil, fmt.Errorf("failed to send INSTREAM command: %v", err)
	}

	// Send data length (4 bytes, big endian) followed by data
	dataLen := len(data)
	lenBytes := []byte{
		byte(dataLen >> 24),
		byte(dataLen >> 16),
		byte(dataLen >> 8),
		byte(dataLen),
	}

	_, err = conn.Write(lenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send data length: %v", err)
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send data: %v", err)
	}

	// Send zero-length chunk to indicate end of data
	_, err = conn.Write([]byte{0, 0, 0, 0})
	if err != nil {
		return nil, fmt.Errorf("failed to send end marker: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	responseStr := string(response[:n])
	return c.parseResponse(responseStr), nil
}

func (c *ClamAVClient) parseResponse(response string) *ScanResult {
	response = strings.TrimSpace(response)

	if strings.Contains(response, "FOUND") {
		// Extract virus name
		parts := strings.Split(response, " ")
		if len(parts) >= 2 {
			virusName := strings.Join(parts[1:len(parts)-1], " ")
			return &ScanResult{
				IsInfected: true,
				Viruses:    []string{virusName},
			}
		}
		return &ScanResult{
			IsInfected: true,
			Viruses:    []string{"Unknown virus"},
		}
	}

	return &ScanResult{
		IsInfected: false,
		Viruses:    []string{},
	}
}

func (c *ClamAVClient) GetVersion() (string, error) {
	conn, err := c.connect()
	if err != nil {
		return "", fmt.Errorf("failed to connect to ClamAV: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("zVERSION\x00"))
	if err != nil {
		return "", fmt.Errorf("failed to send VERSION command: %v", err)
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	return strings.TrimSpace(string(response[:n])), nil
}

// Load configuration from environment variables
func loadConfig() *Config {
	// Load .env file if it exists
	godotenv.Load()

	maxFileSize, _ := strconv.ParseInt(getEnv("APP_MAX_FILE_SIZE", "26214400"), 10, 64) // 25MB default
	maxFilesNumber, _ := strconv.Atoi(getEnv("APP_MAX_FILES_NUMBER", "4"))
	timeoutMs, _ := strconv.Atoi(getEnv("CLAMD_TIMEOUT", "60000"))
	jobExpiration, _ := strconv.Atoi(getEnv("JOB_EXPIRATION", "3600")) // 1 hour default

	return &Config{
		AppPort:           getEnv("APP_PORT", "3000"),
		AppFormKey:        getEnv("APP_FORM_KEY", "FILES"),
		AppMaxFileSize:    maxFileSize,
		AppMaxFilesNumber: maxFilesNumber,
		ClamdIP:           getEnv("CLAMD_IP", "127.0.0.1"),
		ClamdPort:         getEnv("CLAMD_PORT", "3310"),
		ClamdTimeout:      time.Duration(timeoutMs) * time.Millisecond,
		NodeEnv:           getEnv("NODE_ENV", "development"),
		MorganLogFormat:   getEnv("APP_MORGAN_LOG_FORMAT", "combined"),
		RedisURL:          getEnv("REDIS_URL", "redis://localhost:6379"),
		JobExpiration:     jobExpiration,
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Middleware to add ClamAV client to context
func clamAVMiddleware(client *ClamAVClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("clamav", client)
		c.Next()
	}
}

// Middleware to add Redis client to context
func redisMiddleware(client *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("redis", client)
		c.Next()
	}
}

// Middleware for file size limiting
func fileSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}

// Handlers
func scanHandler(config *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		client := c.MustGet("clamav").(*ClamAVClient)

		// Parse multipart form
		err := c.Request.ParseMultipartForm(config.AppMaxFileSize)
		if err != nil {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "Failed to parse multipart form"},
			})
			return
		}

		files := c.Request.MultipartForm.File[config.AppFormKey]
		if len(files) == 0 {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "No files were uploaded"},
			})
			return
		}

		if len(files) > config.AppMaxFilesNumber {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data: ErrorResponse{
					Error: fmt.Sprintf("Too many files uploaded. Max number of files to scan is %d", config.AppMaxFilesNumber),
				},
			})
			return
		}

		var results []ScanResult

		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				c.JSON(http.StatusInternalServerError, APIResponse{
					Success: false,
					Data:    ErrorResponse{Error: fmt.Sprintf("Failed to open file %s", fileHeader.Filename)},
				})
				return
			}
			defer file.Close()

			// Read file data
			data, err := io.ReadAll(file)
			if err != nil {
				c.JSON(http.StatusInternalServerError, APIResponse{
					Success: false,
					Data:    ErrorResponse{Error: fmt.Sprintf("Failed to read file %s", fileHeader.Filename)},
				})
				return
			}

			// Handle empty files
			if len(data) == 0 {
				results = append(results, ScanResult{
					Name:       fileHeader.Filename,
					IsInfected: false,
					Viruses:    []string{},
				})
				continue
			}

			// Scan file
			result, err := client.ScanStream(data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, APIResponse{
					Success: false,
					Data:    ErrorResponse{Error: fmt.Sprintf("Failed to scan file %s: %v", fileHeader.Filename, err)},
				})
				return
			}

			result.Name = fileHeader.Filename
			results = append(results, *result)
		}

		c.JSON(http.StatusOK, APIResponse{
			Success: true,
			Data:    ScanResponse{Result: results},
		})
	}
}

func versionHandler(c *gin.Context) {
	client := c.MustGet("clamav").(*ClamAVClient)

	version, err := client.GetVersion()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Data:    ErrorResponse{Error: err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    VersionResponse{Version: version},
	})
}

func dbSignaturesHandler(c *gin.Context) {
	client := c.MustGet("clamav").(*ClamAVClient)

	// Get local version
	version, err := client.GetVersion()
	if err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Data:    ErrorResponse{Error: err.Error()},
		})
		return
	}

	// Extract local DB version from version string
	parts := strings.Split(version, " ")
	var localVersion string
	if len(parts) > 1 {
		versionParts := strings.Split(parts[1], "/")
		if len(versionParts) > 1 {
			localVersion = versionParts[1]
		}
	}

	// Get remote version (simplified - in production you'd want to use proper DNS TXT lookup)
	// For now, we'll just return the local version as remote
	remoteVersion := localVersion

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data: DBSignaturesResponse{
			LocalClamAVDBSignature:  localVersion,
			RemoteClamAVDBSignature: remoteVersion,
		},
	})
}

func notAllowedHandler(c *gin.Context) {
	c.JSON(http.StatusMethodNotAllowed, APIResponse{
		Success: false,
		Data:    ErrorResponse{Error: "Not allowed."},
	})
}

func scanAsyncHandler(config *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		client := c.MustGet("clamav").(*ClamAVClient)

		// Parse multipart form
		err := c.Request.ParseMultipartForm(config.AppMaxFileSize)
		if err != nil {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "Failed to parse multipart form"},
			})
			return
		}

		files := c.Request.MultipartForm.File[config.AppFormKey]
		if len(files) == 0 {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "No files were uploaded"},
			})
			return
		}

		if len(files) > config.AppMaxFilesNumber {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data: ErrorResponse{
					Error: fmt.Sprintf("Too many files uploaded. Max number of files to scan is %d", config.AppMaxFilesNumber),
				},
			})
			return
		}

		// Generate a job ID
		jobID := uuid.New().String()

		// Create a new job
		job := &Job{
			ID:        jobID,
			Status:    JobStatusPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Start a goroutine to process the scan asynchronously
		go func() {
			var results []ScanResult

			for _, fileHeader := range files {
				file, err := fileHeader.Open()
				if err != nil {
					updateJobStatus(c, jobID, JobStatusFailed, ErrorResponse{
						Error: fmt.Sprintf("Failed to open file %s", fileHeader.Filename),
					})
					return
				}

				// Read file data
				data, err := io.ReadAll(file)
				file.Close()
				if err != nil {
					updateJobStatus(c, jobID, JobStatusFailed, ErrorResponse{
						Error: fmt.Sprintf("Failed to read file %s", fileHeader.Filename),
					})
					return
				}

				// Handle empty files
				if len(data) == 0 {
					results = append(results, ScanResult{
						Name:       fileHeader.Filename,
						IsInfected: false,
						Viruses:    []string{},
					})
					continue
				}

				// Scan file
				result, err := client.ScanStream(data)
				if err != nil {
					updateJobStatus(c, jobID, JobStatusFailed, ErrorResponse{
						Error: fmt.Sprintf("Failed to scan file %s: %v", fileHeader.Filename, err),
					})
					return
				}

				result.Name = fileHeader.Filename
				results = append(results, *result)
			}

			// Update job with results
			updateJobStatus(c, jobID, JobStatusComplete, ScanResponse{Result: results})
		}()

		// Store job in Redis
		redisClient := c.MustGet("redis").(*redis.Client)
		ctx := context.Background()
		jobBytes, _ := json.Marshal(job)
		redisClient.Set(ctx, fmt.Sprintf("job:%s", jobID), jobBytes, time.Duration(config.JobExpiration)*time.Second)

		// Return job ID
		c.JSON(http.StatusAccepted, APIResponse{
			Success: true,
			Data:    JobResponse{JobID: jobID},
		})
	}
}

func scanAsyncRedisHandler(config *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse multipart form
		err := c.Request.ParseMultipartForm(config.AppMaxFileSize)
		if err != nil {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "Failed to parse multipart form"},
			})
			return
		}

		files := c.Request.MultipartForm.File[config.AppFormKey]
		if len(files) == 0 {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "No files were uploaded"},
			})
			return
		}

		if len(files) > config.AppMaxFilesNumber {
			c.JSON(http.StatusBadRequest, APIResponse{
				Success: false,
				Data: ErrorResponse{
					Error: fmt.Sprintf("Too many files uploaded. Max number of files to scan is %d", config.AppMaxFilesNumber),
				},
			})
			return
		}

		// Generate a job ID
		jobID := uuid.New().String()

		// Create a new job
		job := &Job{
			ID:        jobID,
			Status:    JobStatusPending,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Store job in Redis
		redisClient := c.MustGet("redis").(*redis.Client)
		ctx := context.Background()
		jobBytes, _ := json.Marshal(job)
		redisClient.Set(ctx, fmt.Sprintf("job:%s", jobID), jobBytes, time.Duration(config.JobExpiration)*time.Second)

		// Collect file data for Redis message
		var filesData [][]byte
		var fileNames []string

		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				updateJobStatus(c, jobID, JobStatusFailed, ErrorResponse{
					Error: fmt.Sprintf("Failed to open file %s", fileHeader.Filename),
				})
				return
			}

			// Read file data
			data, err := io.ReadAll(file)
			file.Close()
			if err != nil {
				updateJobStatus(c, jobID, JobStatusFailed, ErrorResponse{
					Error: fmt.Sprintf("Failed to read file %s", fileHeader.Filename),
				})
				return
			}

			filesData = append(filesData, data)
			fileNames = append(fileNames, fileHeader.Filename)
		}

		// Create Redis message
		message := ScanMessage{
			JobID:     jobID,
			FileData:  filesData,
			FileNames: fileNames,
		}

		// Publish to Redis
		messageBytes, _ := json.Marshal(message)
		redisClient.Publish(ctx, "scan-jobs", messageBytes)

		// Return job ID
		c.JSON(http.StatusAccepted, APIResponse{
			Success: true,
			Data:    JobResponse{JobID: jobID},
		})
	}
}

func getJobStatusHandler(c *gin.Context) {
	jobID := c.Param("id")
	if jobID == "" {
		c.JSON(http.StatusBadRequest, APIResponse{
			Success: false,
			Data:    ErrorResponse{Error: "Job ID is required"},
		})
		return
	}

	redisClient := c.MustGet("redis").(*redis.Client)
	ctx := context.Background()

	// Get job from Redis
	jobBytes, err := redisClient.Get(ctx, fmt.Sprintf("job:%s", jobID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			c.JSON(http.StatusNotFound, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "Job not found"},
			})
		} else {
			c.JSON(http.StatusInternalServerError, APIResponse{
				Success: false,
				Data:    ErrorResponse{Error: "Failed to retrieve job"},
			})
		}
		return
	}

	var job Job
	if err := json.Unmarshal(jobBytes, &job); err != nil {
		c.JSON(http.StatusInternalServerError, APIResponse{
			Success: false,
			Data:    ErrorResponse{Error: "Failed to parse job data"},
		})
		return
	}

	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    JobStatusResponse{Job: &job},
	})
}

func updateJobStatus(c *gin.Context, jobID string, status string, result interface{}) {
	redisClient := c.MustGet("redis").(*redis.Client)
	ctx := context.Background()

	// Get job from Redis
	jobBytes, err := redisClient.Get(ctx, fmt.Sprintf("job:%s", jobID)).Bytes()
	if err != nil {
		log.Printf("Failed to retrieve job %s: %v", jobID, err)
		return
	}

	var job Job
	if err := json.Unmarshal(jobBytes, &job); err != nil {
		log.Printf("Failed to parse job data for %s: %v", jobID, err)
		return
	}

	// Update job
	job.Status = status
	job.UpdatedAt = time.Now()
	job.Result = result

	// Save job back to Redis
	jobBytes, _ = json.Marshal(job)
	expiration, err := redisClient.TTL(ctx, fmt.Sprintf("job:%s", jobID)).Result()
	if err != nil {
		expiration = time.Hour // Default expiration
	}
	redisClient.Set(ctx, fmt.Sprintf("job:%s", jobID), jobBytes, expiration)
}

func setupRedisScanWorker(config *Config, client *ClamAVClient, redisClient *redis.Client) {
	// Start worker goroutine
	go func() {
		log.Println("Redis scan worker started")
		ctx := context.Background()

		for {
			// Subscribe to scan-jobs channel
			pubsub := redisClient.Subscribe(ctx, "scan-jobs")

			// Create a channel to receive errors from ReceiveMessage
			errorChan := make(chan error, 1)

			// Start a separate goroutine to receive messages
			go func() {
				for {
					msg, err := pubsub.ReceiveMessage(ctx)
					if err != nil {
						log.Printf("Error receiving message: %v", err)
						errorChan <- err
						return
					}

					// Parse message
					var scanMessage ScanMessage
					if err := json.Unmarshal([]byte(msg.Payload), &scanMessage); err != nil {
						log.Printf("Error parsing message: %v", err)
						continue
					}

					// Process scan
					var results []ScanResult

					for i, data := range scanMessage.FileData {
						filename := scanMessage.FileNames[i]

						// Handle empty files
						if len(data) == 0 {
							results = append(results, ScanResult{
								Name:       filename,
								IsInfected: false,
								Viruses:    []string{},
							})
							continue
						}

						// Scan file
						result, err := client.ScanStream(data)
						if err != nil {
							// Update job status with error
							job := &Job{
								ID:        scanMessage.JobID,
								Status:    JobStatusFailed,
								UpdatedAt: time.Now(),
								Result:    ErrorResponse{Error: fmt.Sprintf("Failed to scan file %s: %v", filename, err)},
							}
							jobBytes, _ := json.Marshal(job)
							redisClient.Set(ctx, fmt.Sprintf("job:%s", scanMessage.JobID), jobBytes, time.Duration(config.JobExpiration)*time.Second)
							break
						}

						result.Name = filename
						results = append(results, *result)
					}

					if len(results) == len(scanMessage.FileData) {
						// All files were processed successfully, update job
						job := &Job{
							ID:        scanMessage.JobID,
							Status:    JobStatusComplete,
							UpdatedAt: time.Now(),
							Result:    ScanResponse{Result: results},
						}
						jobBytes, _ := json.Marshal(job)
						redisClient.Set(ctx, fmt.Sprintf("job:%s", scanMessage.JobID), jobBytes, time.Duration(config.JobExpiration)*time.Second)
					}
				}
			}()

			// Wait for an error or context cancellation
			select {
			case <-ctx.Done():
				pubsub.Close()
				return
			case <-errorChan:
				pubsub.Close()
				log.Println("Redis connection error, reconnecting in 5 seconds...")
				time.Sleep(5 * time.Second)
			}
		}
	}()
}

func setupRouter(config *Config, client *ClamAVClient, redisClient *redis.Client) *gin.Engine {
	if config.NodeEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// CORS middleware
	router.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:    []string{"Origin", "Content-Length", "Content-Type"},
	}))

	// Custom middleware
	router.Use(clamAVMiddleware(client))
	router.Use(redisMiddleware(redisClient))
	router.Use(fileSizeLimit(config.AppMaxFileSize))

	// API routes
	v1 := router.Group("/api/v1")
	{
		v1.POST("/scan", scanHandler(config))
		v1.POST("/scan/async", scanAsyncHandler(config))
		v1.POST("/scan/async/redis", scanAsyncRedisHandler(config))
		v1.GET("/jobs/:id", getJobStatusHandler)
		v1.GET("/version", versionHandler)
		v1.GET("/dbsignatures", dbSignaturesHandler)
	}

	// Handle all other routes
	router.NoRoute(notAllowedHandler)
	router.NoMethod(notAllowedHandler)

	return router
}

func main() {
	config := loadConfig()

	// Initialize ClamAV client
	client := NewClamAVClient(config.ClamdIP, config.ClamdPort, config.ClamdTimeout)

	// Initialize Redis client
	opt, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}
	redisClient := redis.NewClient(opt)
	defer redisClient.Close()

	// Test connection to ClamAV
	_, err = client.GetVersion()
	if err != nil {
		log.Fatalf("Cannot connect to ClamAV: %v", err)
	}

	// Test connection to Redis
	ctx := context.Background()
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Cannot connect to Redis: %v", err)
	}

	// Start Redis scan worker
	setupRedisScanWorker(config, client, redisClient)

	router := setupRouter(config, client, redisClient)

	log.Printf("Server starting on port %s", config.AppPort)
	log.Fatal(router.Run(":" + config.AppPort))
}
