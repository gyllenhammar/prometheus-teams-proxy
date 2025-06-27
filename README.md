# Prometheus Alerts to Microsoft Teams Bridge

This Go application listens for incoming Prometheus alert webhook POST requests, formats the alerts into Microsoft Teams Adaptive Cards, and forwards them to a configured Teams webhook URL.

---

## Features

- Receives Prometheus alerts via HTTP POST `/alerts` endpoint  
- Validates incoming requests optionally with a secret token  
- Converts alerts into rich Adaptive Cards for Microsoft Teams  
- Supports environment-based configuration  
- Provides logging with info, debug, and error levels  
- Gracefully shuts down on system interrupt signals  

---

## Configuration

The application reads configuration from environment variables:

| Variable            | Description                                | Default   |
|---------------------|--------------------------------------------|-----------|
| `PORT`              | Port to run the HTTP server on              | `8080`    |
| `LOG_LEVEL`         | Logging level (`info` or `debug`)            | `info`    |
| `EXTERNAL_URL`      | URL to include in Teams card if no alert URL | (empty)   |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams Incoming Webhook URL        | **Required** |
| `WEBHOOK_TOKEN`     | Secret token for validating incoming requests | (empty = disabled) |

---

## Building

Make sure you have Go installed (1.18+ recommended).

```bash
go build -o prometheus-teams-proxy
```

---

## Running

Set the required environment variables and run the binary:

```bash
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/your-webhook-url"
export WEBHOOK_TOKEN="your-secret-token"   # optional
export LOG_LEVEL="debug"                    # optional
export PORT="8080"                          # optional

./prometheus-teams-proxy
```

---

## Docker

Build the Docker image using the provided `Dockerfile`:

```bash
docker build -t prometheus-teams-proxy .
```

Run the container, passing necessary environment variables:

```bash
docker run -d \
  -p 8080:8080 \
  -e TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/your-webhook-url" \
  -e WEBHOOK_TOKEN="your-secret-token" \
  -e LOG_LEVEL="debug" \
  prometheus-teams-proxy
```

---

## Usage

Send Prometheus alerts as JSON POST requests to:

```
http://localhost:<PORT>/alerts
```

The app will:

- Validate the secret token (if configured)  
- Parse and process incoming alerts  
- Send Adaptive Cards to the configured Teams webhook  

---

## Graceful Shutdown

The server listens for interrupt signals (Ctrl+C) and will gracefully shut down.

---

## License

MIT License

---

## Notes

- Ensure your Prometheus alertmanager webhook sends alerts in the expected JSON format.  
- Adaptive Cards follow Microsoft Teams schema v1.4.  
- Debug logs can be enabled by setting `LOG_LEVEL=debug`.  
