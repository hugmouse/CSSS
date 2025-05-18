package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypto/subtle"

	"github.com/gocql/gocql"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidForm            = errors.New("invalid form")
	ErrCredentialsRequired    = errors.New("username and password are required")
	ErrCouldNotHashPassword   = errors.New("could not hash password")
	ErrCouldNotRegisterUser   = errors.New("could not register user")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrFileTooLarge           = errors.New("file too large")
	ErrCouldNotReadFile       = errors.New("could not read file")
	ErrCouldNotReadData       = errors.New("could not read data")
	ErrCouldNotSaveScreenshot = errors.New("could not save screenshot")
	ErrQueryError             = errors.New("query error")
	ErrMissingID              = errors.New("missing id")
	ErrInvalidID              = errors.New("invalid id")
	ErrNotFound               = errors.New("not found")
)

//go:embed static/*
var static embed.FS

//go:embed template/*.gohtml
var templatesFS embed.FS

var tmpl *template.Template
var session *gocql.Session

const (
	ArgonTime       = 2
	ArgonMemory     = 64 * 1024
	ArgonThreads    = 4
	ArgonSaltLength = 16
	ArgonHashLength = 32
)

func main() {
	cluster := gocql.NewCluster("cassandra-1:9042")
	cluster.Keyspace = "db"
	cluster.Consistency = gocql.Quorum

	var err error
	session, err = cluster.CreateSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	tmpl, err = template.ParseFS(templatesFS, "template/*.gohtml")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServer(http.FS(static)))

	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)

	mux.HandleFunc("/upload", authMiddleware(uploadHandler))
	mux.HandleFunc("/screenshots", authMiddleware(listScreenshotsHandler))
	mux.HandleFunc("/screenshot/view", authMiddleware(viewScreenshotHandler))

	log.Println("Server listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	err := tmpl.ExecuteTemplate(w, "index.gohtml", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := tmpl.ExecuteTemplate(w, "register.gohtml", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, ErrInvalidForm.Error(), http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, ErrCredentialsRequired.Error(), http.StatusBadRequest)
		return
	}

	hash, err := computeArgon2(password, ArgonTime, ArgonMemory, ArgonThreads)
	if err != nil {
		http.Error(w, ErrCouldNotHashPassword.Error(), http.StatusInternalServerError)
		return
	}

	err = session.Query(
		`INSERT INTO users (user_id, username, password_hash) VALUES (?, ?, ?)`,
		gocql.MustRandomUUID().String(), username, hash,
	).Exec()
	if err != nil {
		wrapped := fmt.Errorf("%w: %v", ErrCouldNotRegisterUser, err)
		http.Error(w, wrapped.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		err := tmpl.ExecuteTemplate(w, "login.gohtml", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, ErrInvalidForm.Error(), http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, ErrCredentialsRequired.Error(), http.StatusBadRequest)
		return
	}

	var storedHash string
	var userID gocql.UUID
	err = session.Query(
		`SELECT user_id, password_hash FROM users WHERE username = ? LIMIT 1 ALLOW FILTERING`,
		username,
	).Scan(&userID, &storedHash)
	if err != nil {
		http.Error(w, fmt.Errorf("%w: %v", ErrInvalidCredentials, err).Error(), http.StatusUnauthorized)
		return
	}

	err = verifyArgon2(password, storedHash)
	if err != nil {
		http.Error(w, fmt.Errorf("%w: %v", ErrInvalidCredentials, err).Error(), http.StatusUnauthorized)
		return
	}

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    userID.String(),
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/screenshots", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{Name: "session_id", Value: "", Path: "/", Expires: time.Unix(0, 0), HttpOnly: true}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 18) // 2MB
	if err != nil {
		http.Error(w, ErrFileTooLarge.Error(), http.StatusBadRequest)
		return
	}
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, ErrCouldNotReadFile.Error(), http.StatusBadRequest)
		return
	}
	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {
			log.Println("Error closing file:", err)
		}
	}(file)
	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, ErrCouldNotReadData.Error(), http.StatusInternalServerError)
		return
	}

	err = session.Query(
		`INSERT INTO screenshots (screenshot_id, user_id, username, data, type) VALUES (?, ?, ?, ?, ?)`,
		gocql.TimeUUID(),
		r.Context().Value("user_id").(string),
		r.Context().Value("username").(string),
		data,
		handler.Header.Get("Content-Type"),
	).Exec()
	if err != nil {
		http.Error(w, ErrCouldNotSaveScreenshot.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/screenshots", http.StatusSeeOther)
}

func listScreenshotsHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(string)

	type screenshot struct {
		ID   gocql.UUID
		Type string
	}

	var list []screenshot
	iter := session.Query(`SELECT screenshot_id, type FROM screenshots WHERE user_id = ? ALLOW FILTERING`, userID).Iter()
	var s screenshot
	for iter.Scan(&s.ID, &s.Type) {
		list = append(list, s)
	}
	if err := iter.Close(); err != nil {
		http.Error(w, ErrQueryError.Error(), http.StatusInternalServerError)
		return
	}
	err := tmpl.ExecuteTemplate(w, "screenshots.gohtml", list)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func viewScreenshotHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, ErrMissingID.Error(), http.StatusBadRequest)
		return
	}
	scrID, err := gocql.ParseUUID(id)
	if err != nil {
		http.Error(w, ErrInvalidID.Error(), http.StatusBadRequest)
		return
	}
	var data []byte
	var ctype string
	err = session.Query(`SELECT data, type FROM screenshots WHERE screenshot_id = ? ALLOW FILTERING`, scrID).Scan(&data, &ctype)
	if err != nil {
		http.Error(w, ErrNotFound.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(data)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		var username string
		err = session.Query(`SELECT username FROM users WHERE user_id = ? ALLOW FILTERING`, cookie.Value).Scan(&username)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), "user_id", cookie.Value)
		ctx = context.WithValue(ctx, "username", username)
		next(w, r.WithContext(ctx))
	}
}

func computeArgon2(password string, timeCost, memory uint32, threads uint8) (string, error) {
	salt := make([]byte, ArgonSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("%w: could not generate salt: %v", ErrCouldNotHashPassword, err)
	}
	h := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, ArgonHashLength)
	p := []string{
		strconv.FormatUint(uint64(timeCost), 10),
		strconv.FormatUint(uint64(memory), 10),
		strconv.FormatUint(uint64(threads), 10),
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(h),
	}
	return strings.Join(p, ":"), nil
}

func verifyArgon2(password, encoded string) error {
	parts := strings.SplitN(encoded, ":", 5)
	if len(parts) != 5 {
		return fmt.Errorf("%w: malformed hash", ErrInvalidCredentials)
	}
	timeCost64, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("%w: malformed time: %v", ErrInvalidForm, err)
	}
	memory64, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("%w: malformed memory: %v", ErrInvalidForm, err)
	}
	threads64, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return fmt.Errorf("%w: malformed threads: %v", ErrInvalidForm, err)
	}
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("%w: malformed salt: %v", ErrInvalidForm, err)
	}
	hash, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("%w: malformed hash: %v", ErrInvalidForm, err)
	}

	test := argon2.IDKey([]byte(password), salt, uint32(timeCost64), uint32(memory64), uint8(threads64), uint32(len(hash)))
	if subtle.ConstantTimeCompare(test, hash) != 1 {
		return fmt.Errorf("%w: hash mismatch", ErrInvalidCredentials)
	}
	return nil
}
