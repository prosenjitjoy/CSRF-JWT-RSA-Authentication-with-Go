package helper

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"log"
	"main/model"
	"net/http"
	"os"
	"time"

	"github.com/gocql/gocql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	refreshTokenValidTime = time.Hour * 72
	authTokenValidTime    = time.Minute * 15
	privateKeyPath        = "keys/app_rsa"
	publicKeyPath         = "keys/app_rsa.pub"
	emptyString           = ""
)

var (
	session   *gocql.Session = model.DBSession()
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
)

func InitJWT() error {
	signBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}
	return nil
}

type SignedDetails struct {
	FirstName string
	LastName  string
	UserName  string
	Email     string
	UserID    string
	UserType  string
	CSRFToken string
	jwt.RegisteredClaims
}

func CreateNewTokens(user model.User) (authTokenString, refreshTokenString, csrfString string, err error) {
	csrfString, err = generateCSRFSecret()
	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(user.FirstName, user.LastName, user.UserName, user.Email, user.UserID, user.UserType, csrfString)
	if err != nil {
		return
	}
	authTokenString, err = createAuthTokenString(user.FirstName, user.LastName, user.UserName, user.Email, user.UserID, user.UserType, csrfString)
	return
}

func generateCSRFSecret() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), err
}

func createAuthTokenString(first_name, last_name, user_name, email, user_id, user_type, csrfString string) (authTokenString string, err error) {
	authClaims := &SignedDetails{
		FirstName: first_name,
		LastName:  last_name,
		UserName:  user_name,
		Email:     email,
		UserID:    user_id,
		UserType:  user_type,
		CSRFToken: csrfString,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(authTokenValidTime)),
		},
	}

	authTokenString, err = jwt.NewWithClaims(jwt.SigningMethodRS256, authClaims).SignedString(signKey)
	return
}

func createRefreshTokenString(first_name, last_name, user_name, email, user_id, user_type, csrfString string) (refreshTokenString string, err error) {
	refreshClaims := &SignedDetails{
		FirstName: first_name,
		LastName:  last_name,
		UserName:  user_name,
		Email:     email,
		UserID:    user_id,
		UserType:  user_type,
		CSRFToken: csrfString,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenValidTime)),
		},
	}
	refreshTokenString, err = jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims).SignedString(signKey)
	return
}

func SetAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

func NullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	AuthCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &AuthCookie)

	RefreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &RefreshCookie)
}

func GrabCSRFFromReqest(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")
	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}

func CheckAndRefreshToken(oldAuthTokenString, oldRefreshTokenString, oldCSRFString string) (newAuthTokenString, newRefreshTokenString, newCSRFString string, err error) {
	if oldCSRFString == "" {
		log.Println("No CSRF token")
		err = errors.New("Unauthorized")
		return
	}

	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &SignedDetails{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return
	}

	authTokenClaims, ok := authToken.Claims.(*SignedDetails)
	if !ok {
		err = errors.New("authToken is invalid")
		return
	}

	if oldCSRFString != authTokenClaims.CSRFToken {
		log.Println("CSRF token doesn't match jwt")
		err = errors.New("Unauthorized: CSRF token doesn't match jwt")
		return
	}

	if authToken.Valid {
		log.Println("Auth token is valid")

		newCSRFString = authTokenClaims.CSRFToken

		newRefreshTokenString, err = updateRefreshTokenExpire(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if v, ok := err.(jwt.ClaimsValidator); ok {
		log.Println("Auth token is not valid")
		expires_at, expireErr := v.GetExpirationTime()
		if expireErr != nil {
			panic(expireErr)
		}
		if expires_at.Unix() < time.Now().Unix() {
			log.Println("Auth token is expired")
			newAuthTokenString, newCSRFString, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
			if err != nil {
				return
			}
			newRefreshTokenString, err = updateRefreshTokenExpire(oldRefreshTokenString)
			if err != nil {
				return
			}

			newRefreshTokenString, err = updateRefreshTokenCSRF(newRefreshTokenString, newCSRFString)
			return
		} else {
			log.Println("error in auth token")
			err = errors.New("error in auth token")
			return
		}
	} else {
		log.Println("error in auth token")
		err = errors.New("error in auth token")
		return
	}
}

func updateRefreshTokenExpire(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &SignedDetails{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*SignedDetails)
	if !ok {
		err = errors.New("refreshToken is invalid")
		return
	}

	refreshClaims := &SignedDetails{
		FirstName: oldRefreshTokenClaims.FirstName,
		LastName:  oldRefreshTokenClaims.LastName,
		UserName:  oldRefreshTokenClaims.UserName,
		Email:     oldRefreshTokenClaims.Email,
		UserID:    oldRefreshTokenClaims.UserID,
		UserType:  oldRefreshTokenClaims.UserType,
		CSRFToken: oldRefreshTokenClaims.CSRFToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenValidTime)),
		},
	}

	newRefreshTokenString, err = jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims).SignedString(signKey)
	return
}

func updateAuthTokenString(refreshTokenString, oldAuthTokenString string) (newAuthTokenString, csrfString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &SignedDetails{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*SignedDetails)
	if !ok {
		err = errors.New("Error reading jwt claims")
		return
	}

	var refresh_token string
	err = session.Query(`SELECT refresh_token FROM users WHERE last_name = ? AND user_name = ? AND email = ?`, refreshTokenClaims.LastName, refreshTokenClaims.UserName, refreshTokenClaims.Email).Scan(&refreshToken)
	if err != nil {
		panic(err)
	}

	if refresh_token != "" {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &SignedDetails{}, func(t *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})
			if err != nil {
				panic(err)
			}

			oldAuthTokenClaims, ok := authToken.Claims.(*SignedDetails)
			if !ok {
				err = errors.New("Error reading jwt claims")
				return
			}
			csrfString, err = generateCSRFSecret()
			if err != nil {
				panic(err)
			}

			newAuthTokenString, err = createAuthTokenString(oldAuthTokenClaims.FirstName, oldAuthTokenClaims.LastName, oldAuthTokenClaims.UserName, oldAuthTokenClaims.Email, oldAuthTokenClaims.UserID, oldAuthTokenClaims.UserType, csrfString)
			return
		} else {
			log.Println("Refresh token has expired")

			err = session.Query(`UPDATE users SET refresh_token = ? WHERE last_name = ? AND user_name = ? AND email = ?`, emptyString, refreshTokenClaims.LastName, refreshTokenClaims.UserName, refreshTokenClaims.Email).Exec()
			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("Refresh token has been revoked!")
		err = errors.New("Unauthorized")
		return
	}
}

func updateRefreshTokenCSRF(oldRefreshTokenString, newCSRFString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &SignedDetails{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*SignedDetails)
	if !ok {
		err = errors.New("could not read refresh token claims")
		return
	}

	refreshClaims := &SignedDetails{
		FirstName: oldRefreshTokenClaims.FirstName,
		LastName:  oldRefreshTokenClaims.LastName,
		UserName:  oldRefreshTokenClaims.UserName,
		Email:     oldRefreshTokenClaims.Email,
		UserID:    oldRefreshTokenClaims.UserID,
		UserType:  oldRefreshTokenClaims.UserType,
		CSRFToken: newCSRFString,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenValidTime)),
		},
	}

	newRefreshTokenString, err = jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims).SignedString(signKey)
	return
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}
