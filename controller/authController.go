package controller

import (
	"encoding/json"
	"errors"
	"log"
	"main/helper"
	"main/model"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gocql/gocql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type status map[string]interface{}

var session *gocql.Session = model.DBSession()
var validate = validator.New()

func SignUp() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user model.User

		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(status{"error": "invalid json format:"})
			return
		}

		err = validate.Struct(user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(status{"error": "failed to validate json:"})
			return
		}

		var userCount int
		err = session.Query(`SELECT COUNT(*) FROM users WHERE last_name = ? AND user_name = ?`, user.LastName, user.UserName).Scan(&userCount)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "failed to count user_name:"})
			return
		}

		var emailCount int
		err = session.Query(`SELECT COUNT(*) FROM users WHERE last_name = ? AND user_name = ? AND email = ?`, user.LastName, user.UserName, user.Email).Scan(&emailCount)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "failed to count email:"})
			return
		}

		if userCount > 0 || emailCount > 0 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "duplicate user_name or email:"})
			return
		}

		user.Password = helper.HashPassword(user.Password)
		user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UserID = uuid.NewString()

		authTokenString, refreshTokenString, csrfString, err := helper.CreateNewTokens(user)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "failed to generate token:"})
			return
		}

		user.AuthToken = authTokenString
		user.RefreshToken = refreshTokenString

		err = session.Query(`INSERT INTO users (first_name, last_name, user_name, email, password, phone, auth_token, refresh_token, user_type, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, user.FirstName, user.LastName, user.UserName, user.Email, user.Password, user.Phone, user.AuthToken, user.RefreshToken, user.UserType, user.UserID, user.CreatedAt, user.UpdatedAt).Exec()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "failed to insert data:"})
			return
		}

		helper.SetAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
		w.Header().Set("X-CSRF-Token", csrfString)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status{"InsertedID": user.UserID})
	}
}

func SignIn() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user model.User

		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(status{"error": "invalid json format:"})
			return
		}

		if user.Email == "" || user.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(status{"error": "enter last_name, email and phone"})
			return
		}

		usersMap, err := session.Query(`SELECT * FROM getUserByEmail WHERE email = ?`, user.Email).Iter().SliceMap()
		if err != nil || len(usersMap) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "failed to map slice"})
			return
		}

		jsonStr, err := json.Marshal(usersMap[0])
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "json marshling failed"})
			return
		}

		var foundUser model.User
		if err := json.Unmarshal(jsonStr, &foundUser); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "json unmarshling failed"})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(status{"error": err.Error()})
			return
		}

		authToken, refToken, csrfString, err := helper.CreateNewTokens(foundUser)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": "failed to generate token:"})
			return
		}

		helper.SetAuthAndRefreshCookies(&w, authToken, refToken)
		w.Header().Set("X-CSRF-Token", csrfString)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(foundUser)
	}
}

func Dashboard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Joy\n"))
	}
}

func SignOut() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		helper.NullifyTokenCookies(&w, r)
	}
}

func DeleteUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("deleting the user")

		authCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("unauthorized attempt! no auth cookie")
			helper.NullifyTokenCookies(&w, r)
			return
		} else if authErr != nil {
			log.Panic("panic: %+v", authErr)
			helper.NullifyTokenCookies(&w, r)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": authErr.Error()})
			return
		}

		last_name, user_name, email, err := grabUser(authCookie.Value)
		if err != nil {
			log.Panic("panic: %+v", err)
			helper.NullifyTokenCookies(&w, r)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": err.Error()})
			return
		}

		err = session.Query(`DELETE FROM users WHERE last_name = ? AND user_name = ? AND email = ?`, last_name, user_name, email).Exec()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": err.Error()})
			return
		}

		helper.NullifyTokenCookies(&w, r)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status{"msg": "deleted user " + user_name})
	}
}

func grabUser(authTokenString string) (last_name, user_name, email string, err error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &helper.SignedDetails{}, func(t *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*helper.SignedDetails)
	if !ok {
		return "", "", "", errors.New("Error fetching claims")
	}

	return authTokenClaims.LastName, authTokenClaims.UserName, authTokenClaims.Email, nil
}
