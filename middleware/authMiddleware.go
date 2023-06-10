package middleware

import (
	"encoding/json"
	"log"
	"main/helper"
	"net/http"
)

type status map[string]interface{}

func Authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("In auth restricted section")

		authCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("Unauthorized attempt! No auth cookie")
			helper.NullifyTokenCookies(&w, r)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(status{"error": authErr.Error()})
			return
		} else if authErr != nil {
			log.Panic("panic: %+v", authErr)
			helper.NullifyTokenCookies(&w, r)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": authErr.Error()})
			return
		}

		refreshCookie, refreshErr := r.Cookie("RefreshToken")
		if refreshErr == http.ErrNoCookie {
			log.Println("unauthorized attempt! no refresh cookie")
			helper.NullifyTokenCookies(&w, r)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(status{"error": refreshErr.Error()})
			return
		} else if refreshErr != nil {
			log.Panic("panic: %+v", refreshErr)
			helper.NullifyTokenCookies(&w, r)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(status{"error": refreshErr.Error()})
			return
		}

		// fix here
		reqeustCSRFString := helper.GrabCSRFFromReqest(r)

		authTokenString, refreshTokenString, csrfString, err := helper.CheckAndRefreshToken(authCookie.Value, refreshCookie.Value, reqeustCSRFString)
		if err != nil {
			if err.Error() == "Unauthorized" {
				log.Println("Unauthorized attempt! JWT's not valid!")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(status{"error": "JWT is not valid:"})
				return
			} else {
				log.Println("error not nil")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(status{"error": "JWT is not valid:"})
				return
			}
		}

		log.Println("Successfully recreated jwt")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		helper.SetAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
		w.Header().Set("X-CSRF-Token", csrfString)

		next.ServeHTTP(w, r)
	})
}
