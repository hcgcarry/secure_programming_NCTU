package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
)

type User struct {
	Username sql.NullString
	Flag     sql.NullString
}

func main() {
	store := sessions.NewCookieStore([]byte(os.Getenv("SECRET_KEY")))
	templates, _ := template.ParseGlob("templates/*.html")

	db, err := sql.Open("mysql", "user:pa55w0rd@tcp(database:3306)/db")
	if err != nil {
		log.Println(err)
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(30)
	db.SetMaxIdleConns(10)

	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		filename := strings.TrimPrefix(r.URL.Path, "/static/")
		w.Write([]byte(filepath.Join("./static/", filename)))
		content, err := os.ReadFile(filepath.Join("./static/", filename))
		if err != nil {
			http.Error(w, "404 jfsdkfsjNot found", http.StatusNotFound)
			return
		}
		w.Header().Add("Content-Type", mime.TypeByExtension(filepath.Ext(filename)))
		w.Write([]byte(content))
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		switch r.Method {
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}


			var username string
			username = r.FormValue("username")
			// query := fmt.Sprintf(
			// 	"SELECT username, password FROM users WHERE username='%s' and password='%s'",
			// 	r.FormValue("username"), r.FormValue("password"))
			// err := db.QueryRow(query).Scan(&username, &password)

			// if err != nil {
			// 	log.Println(err)
			// 	w.Write([]byte("Incorrect username or password"))
			// 	return
			// }

			session, _ := store.Get(r, "session")
			session.Values["username"] = username
			err = session.Save(r, w)
			if err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)

		default:
			templates.ExecuteTemplate(w, "login.html", nil)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")

		username := session.Values["username"]

		if session.Values["username"] == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		w.Write([]byte(username.(string)))
		query := fmt.Sprintf("SELECT username, flag FROM users WHERE username='%s'", username)
		w.Write([]byte(query))
		// query = "SELECT username, flag FROM users WHERE username='admin'"
		row := db.QueryRow(query)
		var user User
		row.Scan(&user.Username, &user.Flag)

		templates.ExecuteTemplate(w, "index.html", user)
	})

	http.ListenAndServe(":9453", nil)
}
