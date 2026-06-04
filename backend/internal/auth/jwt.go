// Package auth handles password hashing (bcrypt) and JWT issue/verify.
// Kept tiny on purpose — JWT is a library call, not a framework.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// ctxKey is an unexported type so handlers can only retrieve the claims via
// the helpers in this package — avoids string-key collisions in context.
type ctxKey struct{}

var userCtxKey = ctxKey{}

// Claims is what we sign into each JWT. Subject = user ID as a string so we can
// look the user up; Username is duplicated for convenience on the frontend.
type Claims struct {
	UserID   int    `json:"uid"`
	Username string `json:"un"`
	jwt.RegisteredClaims
}

// Manager issues and verifies HS256 JWTs with a shared secret loaded from env.
// HS256 is fine for a single-service prototype; a multi-service deployment
// would prefer RS256 with rotated keys.
type Manager struct {
	secret []byte
	ttl    time.Duration
}

func NewManager(secret string, ttl time.Duration) *Manager {
	return &Manager{secret: []byte(secret), ttl: ttl}
}

// Hash returns a bcrypt hash. DefaultCost (10) is a sensible 2025 baseline —
// fast enough for login UX (~60ms on a laptop) but slow enough to discourage
// brute force.
func Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return string(b), nil
}

// Verify is a constant-time comparison (bcrypt handles the timing for us).
func Verify(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// Issue mints a signed JWT for the given user.
func (m *Manager) Issue(userID int, username string) (string, error) {
	now := time.Now()
	c := Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
			Issuer:    "tenexai-assessment",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	s, err := tok.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return s, nil
}

// Parse verifies the signature and expiration, returning the claims on success.
func (m *Manager) Parse(token string) (*Claims, error) {
	var c Claims
	t, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("invalid token")
	}
	return &c, nil
}

// WithClaims tucks the verified claims into the request context so downstream
// handlers can ask "who is the caller?" without re-parsing the header.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, userCtxKey, c)
}

// FromContext is the read side of WithClaims. Returns (nil, false) on unauth.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(userCtxKey).(*Claims)
	return c, ok
}
