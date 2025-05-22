# ClamAV REST API - Go Implementation


## Features

- **File Scanning**: Upload files for virus scanning via REST API
- **Version Information**: Get ClamAV version information
- **Database Signatures**: Check local and remote virus database versions
- **Multiple File Support**: Scan multiple files in a single request
- **Docker Support**: Ready-to-use Docker containers
- **CORS Enabled**: Cross-origin resource sharing support

## API Endpoints

- `POST /api/v1/scan` - Scan uploaded files
- `GET /api/v1/version` - Get ClamAV version
- `GET /api/v1/dbsignatures` - Get database signature information

## Quick Start

### Prerequisites

- Go 1.21 or higher
- Running ClamAV daemon (clamd)

### Running with Docker Compose (Recommended)

```bash
# Clone and build
git clone <your-repo>
cd clamav-rest-api-go
docker-compose up -d
```

### Running Locally

```bash
# Install dependencies
go mod tidy

# Copy environment file
cp .env.example .env

# Edit .env file with your settings
# Start the server
go run cmd/clamav/main.go
```

### Building

```bash
# Build binary
go build -o api ./cmd/clamav

# Run binary
./api
```

## Configuration

Configure via environment variables or `.env` file:

- `APP_PORT` - Server port (default: 3000)
- `APP_FORM_KEY` - Form field name for file uploads (default: FILES)
- `APP_MAX_FILE_SIZE` - Maximum file size in bytes (default: 26214400)
- `APP_MAX_FILES_NUMBER` - Maximum number of files per request (default: 4)
- `CLAMD_IP` - ClamAV daemon IP address (default: 127.0.0.1)
- `CLAMD_PORT` - ClamAV daemon port (default: 3310)
- `CLAMD_TIMEOUT` - Connection timeout in milliseconds (default: 60000)
- `NODE_ENV` - Environment mode (default: development)

## Usage Examples

### cURL Example

```bash
curl -X POST http://localhost:3000/api/v1/scan \
  -F "FILES=@test1.txt" \
  -F "FILES=@test2.txt"
```

### Response Format

```json
{
  "success": true,
  "data": {
    "result": [
      {
        "name": "test1.txt",
        "is_infected": false,
        "viruses": []
      },
      {
        "name": "test2.txt",
        "is_infected": true,
        "viruses": ["Win.Test.EICAR_HDB-1"]
      }
    ]
  }
}
```

### Version Check

```bash
curl http://localhost:3000/api/v1/version
```

### Database Signatures

```bash
curl http://localhost:3000/api/v1/dbsignatures
```

## Differences from Node.js Version

1. **Performance**: Significantly faster startup and lower memory usage
2. **Concurrency**: Better handling of concurrent requests
3. **Dependencies**: Fewer external dependencies
4. **Binary**: Compiles to a single binary for easy deployment
5. **Error Handling**: More robust error handling and logging

## Docker Images

### Building Your Own Image

```bash
docker build -t clamav-rest-api-go .
```

### Running with Docker

```bash
docker run -d -p 8080:3000 \
  -e APP_PORT=3000 \
  -e CLAMD_IP=your-clamav-host \
  -e APP_FORM_KEY=FILES \
  clamav-rest-api-go
```

## Testing

### Test File Creation

```bash
# Create a test file
echo "Hello World" > test.txt

# Create EICAR test virus file (harmless test file)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
```

### Manual Testing

```bash
# Test clean file
curl -X POST http://localhost:3000/api/v1/scan -F "FILES=@test.txt"

# Test virus file (should be detected)
curl -X POST http://localhost:3000/api/v1/scan -F "FILES=@eicar.txt"
```

## Health Checks

The application includes health check endpoints for monitoring:

```bash
# Check if service is running
curl http://localhost:3000/api/v1/version
```

## Logging

The application uses Gin's built-in logging. In production mode, logs are minimized for better performance.

## Security Considerations

- File size limits are enforced
- Maximum number of files per request is limited
- Input validation on all endpoints
- No file persistence (files are scanned in memory)
- Non-root user in Docker container

## Performance Notes

- Uses connection pooling for ClamAV connections
- Efficient memory usage with streaming
- Concurrent file processing
- Optimized Docker image with multi-stage builds

## Troubleshooting

### Common Issues

1. **Cannot connect to ClamAV**: Ensure ClamAV daemon is running and accessible
2. **File size errors**: Check `APP_MAX_FILE_SIZE` setting
3. **Too many files**: Check `APP_MAX_FILES_NUMBER` setting
4. **Port conflicts**: Change `APP_PORT` if port 3000 is in use

### Debug Mode

Set `NODE_ENV=development` for verbose logging.

## License

MIT License 
