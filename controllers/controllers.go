package controllers

import (
	"fmt"
	"net/http"

	"github.com/joeydtaylor/hermes/middleware/auth"
)

func Index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, from the Index Controller!"))
}

func ProtectedPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, from the ProtectedPage Controller!"))
}

func RoleProtectedPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, from the RoleProtectedPage Controller!"))
}

func AdminProtectedPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, from the AdminProtectedPage Controller!"))
}

func UserProtectedPage(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, from the UserProtectedNameController!"))
}

func GetUserPage(w http.ResponseWriter, r *http.Request) {
	user := auth.ProvideAuthentication().GetUser(r.Context())
	response := fmt.Sprintf("Hello %s, from the GetUserPage! You authenticated via %s and your role is %s!", user.Username, user.AuthenticationSource.Provider, user.Role.Name)
	w.Write([]byte(response))
}
