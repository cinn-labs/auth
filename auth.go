package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
)

type Model struct {
	AuthMiddleware        func(http.ResponseWriter, *http.Request, http.HandlerFunc)
	GenerateToken         func(clms map[string]interface{}) (string, *jwt.Token)
	GetClaimsByToken      func(tokenStr string) (map[string]interface{}, error)
	GetAuthTokenByRequest func(r *http.Request) string
	GetIDFromTokenClaims  func(auth *Model, token string, key string) int
}

func Generate(signature string) *Model {
	authMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			claims := token.Claims.(jwt.MapClaims)

			if claims["revoked"] == true {
				return nil, errors.New("Revoked Token")
			}

			return []byte(signature), nil
		},

		Extractor: func(r *http.Request) (string, error) {
			authHeader := r.Header.Get("Auth")
			if authHeader == "" {
				return "", nil // No error, just no token
			}

			authHeaderParts := strings.Split(authHeader, " ")
			if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
				return "", errors.New("Authorization header format must be Bearer {token}")
			}

			return authHeaderParts[1], nil
		},

		// When set, the middleware verifies that tokens are signed with the specific signing algorithm
		// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
		// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
		SigningMethod: jwt.SigningMethodHS256,
	}).HandlerWithNext

	generateToken := func(clms map[string]interface{}) (string, *jwt.Token) {
		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims)
		claims["exp"] = time.Now().Add(time.Hour * 24 * 3).Unix()

		for key, value := range clms {
			claims[key] = value
		}

		tokenString, _ := token.SignedString([]byte(signature))

		return tokenString, token
	}

	getClaimsByToken := func(tokenStr string) (map[string]interface{}, error) {
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(signature), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return claims, nil
		} else {
			return nil, err
		}
	}

	getAuthTokenByRequest := func(r *http.Request) string {
		fullToken := r.Header.Get("Auth")
		tokenSpl := strings.Split(fullToken, " ")
		return tokenSpl[1]
	}

	getIDFromTokenClaims := func(auth *Model, token string, key string) int {
		claims, _ := auth.GetClaimsByToken(token)
		return int(claims[key].(float64))
	}

	return &Model{authMiddleware, generateToken, getClaimsByToken, getAuthTokenByRequest, getIDFromTokenClaims}
}
