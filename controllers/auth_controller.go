package controllers

import (
	"dr4ke-c2/server/database"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	AdminUser     = "admin"
	AdminPassword = "admin"
)

type AuthController struct {
	sessionMutex sync.Mutex
	sessionValid bool
	serverKey    string
	store        database.Store
}

func NewAuthController(serverKey string, store database.Store) *AuthController {
	return &AuthController{
		sessionValid: false,
		serverKey:    serverKey,
		store:        store,
	}
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	if loginData.Username == AdminUser && loginData.Password == AdminPassword {
		c.sessionMutex.Lock()
		c.sessionValid = true
		c.sessionMutex.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_session",
			Value:    "authenticated",
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
		})

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"token":   "dummy-token-for-compatibility",
			"csrf":    "dummy-csrf-for-compatibility",
		})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid username or password",
		})
	}
}

func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	c.sessionMutex.Lock()
	c.sessionValid = false
	c.sessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
	})
}

func (c *AuthController) VerifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_session")

	if err == nil && cookie.Value == "authenticated" && c.isSessionValid() {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": true,
		})
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
		})
	}
}

func (c *AuthController) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/login" ||
			r.URL.Path == "/auth/verify" ||
			strings.HasPrefix(r.URL.Path, "/static/") ||
			r.URL.Path == "/register" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("auth_session")

		if err == nil && cookie.Value == "authenticated" && c.isSessionValid() {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

func (c *AuthController) isSessionValid() bool {
	c.sessionMutex.Lock()
	defer c.sessionMutex.Unlock()
	return c.sessionValid
}
