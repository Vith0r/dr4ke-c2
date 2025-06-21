package controllers

import (
	"golang.org/x/time/rate"
	"net/http"
	"sync"
)

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}
func (r *RateLimiter) Allow(req *http.Request) bool {
	ip := getClientIP(req)
	limiter := r.getLimiter(ip)
	return limiter.Allow()
}
func (r *RateLimiter) getLimiter(ip string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	limiter, exists := r.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(5), 5) 
		r.limiters[ip] = limiter
	}
	return limiter
}
