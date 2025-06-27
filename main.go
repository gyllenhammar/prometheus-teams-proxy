package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
	"context"
	"os/signal"
	"syscall"
)

// Config structure for app-wide settings
type Config struct {
	Port        string
	LogLevel    string
	ExternalURL string
	WebhookURL  string
	SecretToken string
	DebugMode   bool
}

var config Config

func init() {
	config = Config{
		Port:        getEnv("PORT", "8080"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		ExternalURL: os.Getenv("EXTERNAL_URL"),
		WebhookURL:  os.Getenv("TEAMS_WEBHOOK_URL"),
		SecretToken: os.Getenv("WEBHOOK_TOKEN"),
	}
	config.DebugMode = config.LogLevel == "debug"
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func logInfo(msg string, args ...interface{}) {
	log.Printf("[INFO] "+msg, args...)
}

func logDebug(msg string, args ...interface{}) {
	if config.DebugMode {
		log.Printf("[DEBUG] "+msg, args...)
	}
}

func logError(msg string, args ...interface{}) {
	log.Printf("[ERROR] "+msg, args...)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Alert and Teams card structs

type PrometheusAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	EndsAt      string            `json:"endsAt"`
}

type PrometheusPayload struct {
	Alerts []PrometheusAlert `json:"alerts"`
}

type Fact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

type AdaptiveCardContent struct {
	Schema  string        `json:"$schema"`
	Type    string        `json:"type"`
	Version string        `json:"version"`
	Body    []interface{} `json:"body"`
}

type Attachment struct {
	ContentType string              `json:"contentType"`
	Content     AdaptiveCardContent `json:"content"`
}

type TeamsMessage struct {
	Summary     string       `json:"summary"`
	Title       string       `json:"title"`
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments"`
}

func buildAdaptiveCard(alert PrometheusAlert) TeamsMessage {
	title := alert.Annotations["display_name"]
	if title == "" {
		title = alert.Annotations["summary"]
	}
	if title == "" {
		title = alert.Labels["alertname"]
	}

	description := alert.Annotations["description"]
	if description == "" {
		description = "No description provided."
	}

	startTimeFormatted := alert.StartsAt
	if t, err := time.Parse(time.RFC3339, alert.StartsAt); err == nil {
		startTimeFormatted = t.Format("2006-01-02 15:04:05 MST")
	}

	labelOrNA := func(m map[string]string, key string) string {
		if v, ok := m[key]; ok {
			return v
		}
		return "N/A"
	}

	facts := []Fact{
		{Title: "Alert", Value: labelOrNA(alert.Labels, "alertname")},
		{Title: "Severity", Value: labelOrNA(alert.Labels, "severity")},
		{Title: "Identifier", Value: labelOrNA(alert.Labels, "identifier")},
		{Title: "Tenant", Value: labelOrNA(alert.Labels, "tenant")},
		{Title: "Namespace", Value: labelOrNA(alert.Labels, "namespace")},
		{Title: "Site", Value: labelOrNA(alert.Labels, "site")},
		{Title: "Service", Value: labelOrNA(alert.Labels, "service_name")},
		{Title: "Virtual Host", Value: labelOrNA(alert.Labels, "vh_name")},
		{Title: "Start Time", Value: startTimeFormatted},
	}

	body := []interface{}{
		map[string]interface{}{
			"type":   "TextBlock",
			"size":   "Large",
			"weight": "Bolder",
			"text":   "🚨 " + title,
			"wrap":   true,
		},
		map[string]interface{}{
			"type": "TextBlock",
			"text": description,
			"wrap": true,
		},
		map[string]interface{}{
			"type":  "FactSet",
			"facts": facts,
		},
	}

	if url := alert.Annotations["generatorURL"]; url != "" {
		body = append(body, map[string]interface{}{
			"type": "ActionSet",
			"actions": []map[string]interface{}{
				{
					"type":  "Action.OpenUrl",
					"title": "View in Prometheus",
					"url":   url,
				},
			},
		})
	} else if config.ExternalURL != "" {
		body = append(body, map[string]interface{}{
			"type": "ActionSet",
			"actions": []map[string]interface{}{
				{
					"type":  "Action.OpenUrl",
					"title": "Open Compass",
					"url":   config.ExternalURL,
				},
			},
		})
	}

	card := AdaptiveCardContent{
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Type:    "AdaptiveCard",
		Version: "1.4",
		Body:    body,
	}

	return TeamsMessage{
		Summary:     title,
		Title:       "🚨 " + title,
		Text:        description,
		Attachments: []Attachment{{ContentType: "application/vnd.microsoft.card.adaptive", Content: card}},
	}
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Only POST allowed")
		return
	}

	if config.WebhookURL == "" {
		writeJSONError(w, http.StatusInternalServerError, "TEAMS_WEBHOOK_URL not set")
		logError("TEAMS_WEBHOOK_URL not set")
		return
	}

	if config.SecretToken != "" {
		token := r.Header.Get("X-Webhook-Token")
		if token != config.SecretToken {
			writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
			logError("Unauthorized access attempt from %s", r.RemoteAddr)
			return
		}
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Failed to read body")
		logError("Failed to read request body: %v", err)
		return
	}

	logInfo("Received alert POST from %s", r.RemoteAddr)
	if config.DebugMode {
		headers, _ := json.Marshal(r.Header)
		logDebug("Headers: %s", headers)
		bodyPreview := string(bodyBytes)
		if len(bodyPreview) > 1000 {
			bodyPreview = bodyPreview[:1000] + "... (truncated)"
		}
		logDebug("Body: %s", bodyPreview)
	}

	var payload PrometheusPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON payload")
		logError("Invalid JSON: %v", err)
		return
	}

	if len(payload.Alerts) == 0 {
		writeJSONError(w, http.StatusBadRequest, "No alerts found")
		logInfo("Received payload with 0 alerts")
		return
	}

	logInfo("Parsed %d alert(s)", len(payload.Alerts))
	client := &http.Client{Timeout: 10 * time.Second}

	for _, alert := range payload.Alerts {
		msg := buildAdaptiveCard(alert)
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to marshal Teams message")
			logError("Failed to marshal Teams message: %v", err)
			return
		}

		req, err := http.NewRequest(http.MethodPost, config.WebhookURL, bytes.NewReader(msgBytes))
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Failed to create POST request")
			logError("Failed to create POST request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Error posting to Teams webhook")
			logError("Failed to send to Teams: %v", err)
			return
		}
		defer resp.Body.Close()

		logInfo("Posted alert to Teams, response status: %d", resp.StatusCode)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != 202 {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("Teams webhook responded with status %d", resp.StatusCode))
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"alert_count": len(payload.Alerts),
	})
}

func main() {
	logInfo("Starting server on port %s", config.Port)
	if config.ExternalURL != "" {
		logInfo("Using external URL fallback: %s", config.ExternalURL)
	}

	http.HandleFunc("/alerts", alertHandler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Addr: ":" + config.Port}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down...")
	srv.Shutdown(context.Background())
}
