package main

import (
	"C"
	"strings"
	"syscall"
	"unsafe"
)

var lastResult string

func Execute(command *C.char) C.int {
	cmd := C.GoString(command)
	parts := strings.Fields(cmd)

	if len(parts) == 0 {
		return 0
	}

	switch strings.ToLower(parts[0]) {
	case "msgbox":
		if len(parts) < 2 {
			showMessageBox("Drake C2", "Plugin funcionando!")
			lastResult = "MessageBox displayed with default message"
		} else {
			message := strings.Join(parts[1:], " ")
			showMessageBox("Drake C2", message)
			lastResult = "MessageBox displayed: " + message
		}
		return 1
	case "msgbox_info":
		if len(parts) < 3 {
			lastResult = "Usage: msgbox_info <title> <message>"
		} else {
			title := parts[1]
			message := strings.Join(parts[2:], " ")
			showMessageBoxInfo(title, message)
			lastResult = "Info MessageBox displayed: " + title + " - " + message
		}
		return 1
	case "msgbox_warning":
		if len(parts) < 3 {
			lastResult = "Usage: msgbox_warning <title> <message>"
		} else {
			title := parts[1]
			message := strings.Join(parts[2:], " ")
			showMessageBoxWarning(title, message)
			lastResult = "Warning MessageBox displayed: " + title + " - " + message
		}
		return 1
	case "msgbox_error":
		if len(parts) < 3 {
			lastResult = "Usage: msgbox_error <title> <message>"
		} else {
			title := parts[1]
			message := strings.Join(parts[2:], " ")
			showMessageBoxError(title, message)
			lastResult = "Error MessageBox displayed: " + title + " - " + message
		}
		return 1
	}

	return 0
}

func GetResult() *C.char {
	return C.CString(lastResult)
}

func GetCommands() *C.char {
	commands := "msgbox,msgbox_info,msgbox_warning,msgbox_error"
	return C.CString(commands)
}

func GetPluginInfo() *C.char {
	info := "MessageBox Plugin v1.0 - Display message boxes with different styles"
	return C.CString(info)
}

func showMessageBox(title, message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")

	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	messageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)), 0)
}

func showMessageBoxInfo(title, message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")

	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	messageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)), 0x40)
}

func showMessageBoxWarning(title, message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")

	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	messageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)), 0x30)
}

func showMessageBoxError(title, message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")

	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	messageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)), 0x10)
}

func main() {}
