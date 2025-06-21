package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type UploadController struct {
	uploadDir string
}

func NewUploadController(uploadDir string) *UploadController {
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create upload directory: %v", err))
	}
	return &UploadController{uploadDir: uploadDir}
}

func (c *UploadController) HandleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".bat" {
		http.Error(w, "Only .bat files are supported", http.StatusBadRequest)
		return
	}
	filename := c.generateSecureFilename(header.Filename)
	filepath := filepath.Join(c.uploadDir, filename)
	dst, err := os.Create(filepath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, file); err != nil {
		os.Remove(filepath) 
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)
	fileURL := fmt.Sprintf("%s/uploads/%s", baseURL, filename)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "File uploaded successfully",
		"url":      fileURL,
		"filename": filename,
		"type":     "bat",
	})
}

func (c *UploadController) generateSecureFilename(originalName string) string {
	ext := filepath.Ext(originalName)
	timestamp := time.Now().Format("20060102-150405")
	hasher := sha256.New()
	hasher.Write([]byte(originalName + timestamp))
	hash := hex.EncodeToString(hasher.Sum(nil))[:12]
	return fmt.Sprintf("%s-%s%s", timestamp, hash, ext)
}

func (c *UploadController) ValidateFile(file *multipart.FileHeader) error {
	if file.Size > 100*1024*1024 {
		return fmt.Errorf("file too large (max 100MB)")
	}
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".bat" {
		return fmt.Errorf("only .bat files are supported")
	}

	return nil
}
