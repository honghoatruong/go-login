package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

const (
	dbDriver = "mysql"
	dbUser   = "root"
	dbPass   = ""
	dbName   = "jcmain"
	dbRemote = ""
)

var current_id int

func main() {
	// Create a new router
	r := mux.NewRouter()

	// Define your HTTP routes using the router
	r.HandleFunc("/", loginPageHandler)
	r.HandleFunc("/logout", logoutPageHandler)
	r.HandleFunc("/user", createUserHandler).Methods("POST")
	r.HandleFunc("/user/{id}", getUserHandler).Methods("GET")
	r.HandleFunc("/user/{id}", updateUserHandler).Methods("PUT")
	r.HandleFunc("/user/{id}", deleteUserHandler).Methods("DELETE")
	r.HandleFunc("/login_", loginHandler).Methods("POST")
	r.HandleFunc("/current_user", getCurrentUserHandler).Methods("POST")
	// r.HandleFunc("/current_auth", getAuthDiningHandler).Methods("GET")
	r.HandleFunc("/login", loginPageHandler)
	r.HandleFunc("/home", homePageHandler)

	// Start the HTTP server on port 8080
	log.Println("Server listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

type AuthResquestBody struct {
	Secret_key string
	Uid        string
	Salt       string
	Token      string
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@"+dbRemote+"/"+dbName)
		if err != nil {
			log.Println(err.Error())
			panic(err.Error())
		}
		defer db.Close()

		// Check in database
		user, err := loginUser(db, email, password)
		// log.Println("user", user)
		if err != nil {
			http.Error(w, "Name/Password not correct", http.StatusNotFound)
			return
		}
		// Perform authentication logic here (e.g., check against a database).
		if user != nil {
			// Save session
			cookie := &http.Cookie{
				Name:  "ID",
				Value: strconv.Itoa(user.ID),
				// Value:  , // Some encoded value
				Path:   "/",   // Otherwise it defaults to the /login if you create this on /login (standard cookie behaviour)
				MaxAge: 86400, // One day
			}

			http.SetCookie(w, cookie)

			cookie = &http.Cookie{
				Name:  "LOGGED",
				Value: strconv.Itoa(1),
				// Value:  , // Some encoded value
				Path:   "/",   // Otherwise it defaults to the /login if you create this on /login (standard cookie behaviour)
				MaxAge: 86400, // One day
			}

			http.SetCookie(w, cookie)
			current_id = user.ID

			// Successful login, redirect to a welcome page.
			http.Redirect(w, r, "/home", http.StatusSeeOther)

		}

		// Invalid credentials, show the login page with an error message.
		fmt.Fprintf(w, "Invalid credentials. Please try again.")
		return
	}

	// If not a POST request, serve the login page template.
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}
func homePageHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	id := ""
	cookies := r.Cookies()
	for _, c := range cookies {
		if c.Name == "ID" {
			// Found! Use it!
			id = c.Value
			break
		}
	}

	userID, _ := strconv.Atoi(id)

	// Call the GetUser function to fetch the user data from the database
	user, err := GetUser(db, userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	d := struct {
		Name string
	}{
		Name: user.Name,
	}
	tmpl, err := template.ParseFiles("templates/home.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, d)
}
func logoutPageHandler(w http.ResponseWriter, r *http.Request) {
	c := &http.Cookie{
		Name:    "ID",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),

		HttpOnly: true,
	}

	http.SetCookie(w, c)
	c = &http.Cookie{
		Name:    "LOGGED",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),

		HttpOnly: true,
	}
	http.SetCookie(w, c)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// function handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@"+dbRemote+"/"+dbName)
	if err != nil {
		log.Println(err.Error())
		panic(err.Error())
	}
	defer db.Close()

	// Parse JSON data from the request body
	var account Account
	er := json.NewDecoder(r.Body).Decode(&account)
	if er != nil {
		http.Error(w, er.Error(), http.StatusBadRequest)
		return
	}

	user, err := loginUser(db, account.Name, account.Password)
	if err != nil {
		http.Error(w, "Name/Password not correct", http.StatusNotFound)
		return
	}

	// Convert the user object to JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(user)

}

func loginUser(db *sql.DB, email, password string) (*User, error) {
	query := "SELECT customer_id, firstname, email, password FROM `oc_customer` WHERE `email` = ? AND (`password` = SHA1(CONCAT(salt, SHA1(CONCAT(salt, SHA1(?))))) OR `password` = md5(?))"
	// query := "SELECT * FROM `oc_customer` WHERE `email` = ? AND `password` =  ?"
	row := db.QueryRow(query, email, password, password)

	user := &User{}
	err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@"+dbRemote+"/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// Parse JSON data from the request body
	var user User
	er := json.NewDecoder(r.Body).Decode(&user)
	log.Println(r.Body)

	if er != nil {
		http.Error(w, er.Error(), http.StatusBadRequest)
		return
	}
	// log.Println(user)

	CreateUser(db, user.Name, user.Email, user.Password)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "User created successfully")
}

func CreateUser(db *sql.DB, name, email, password string) error {
	query := "INSERT INTO oc_customer (name, email, password) VALUES (?, ?, ?)"

	_, err := db.Exec(query, name, email, password)
	// log.Println(name, email, password)
	if err != nil {
		return err
	}
	return nil
}

type User struct {
	ID       int
	Name     string
	Email    string
	Password string
}
type Account struct {
	Name     string
	Password string
}
type Customer struct {
	ID int
}

type Email struct {
	Email string
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// Get the 'id' parameter from the URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	// Convert 'id' to an integer
	userID, err := strconv.Atoi(idStr)

	// Call the GetUser function to fetch the user data from the database
	user, err := GetUser(db, userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Convert the user object to JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(user)
}
func GetUser(db *sql.DB, id int) (*User, error) {
	query := "SELECT customer_id, firstname, email, password FROM oc_customer WHERE customer_id = ?"
	row := db.QueryRow(query, id)

	user := &User{}
	err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password)
	if err != nil {
		return nil, err
	}

	return user, nil
}
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// Get the 'id' parameter from the URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	// Convert 'id' to an integer
	userID, err := strconv.Atoi(idStr)

	var user User
	err = json.NewDecoder(r.Body).Decode(&user)

	// Call the GetUser function to fetch the user data from the database
	UpdateUser(db, userID, user.Name, user.Email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	fmt.Fprintln(w, "User updated successfully")
}
func UpdateUser(db *sql.DB, id int, name, email string) error {
	query := "UPDATE oc_customer SET name = ?, email = ? WHERE customer_id = ?"
	_, err := db.Exec(query, name, email, id)
	if err != nil {
		return err
	}
	return nil
}
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	// Get the 'id' parameter from the URL
	vars := mux.Vars(r)
	idStr := vars["id"]

	// Convert 'id' to an integer
	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid 'id' parameter", http.StatusBadRequest)
		return
	}

	user := DeleteUser(db, userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	fmt.Fprintln(w, "User deleted successfully")

	// Convert the user object to JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(user)
}
func DeleteUser(db *sql.DB, id int) error {
	query := "DELETE FROM oc_customer WHERE customer_id = ?"
	_, err := db.Exec(query, id)
	if err != nil {
		return err
	}
	return nil
}

type RequestBody struct {
	Secret_key string
}

func getCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t RequestBody
	err := decoder.Decode(&t)
	if err != nil {
		panic(err)
	}
	if t.Secret_key != "Vf@20212" {
		return
	}

	db, err := sql.Open(dbDriver, dbUser+":"+dbPass+"@/"+dbName)
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	// Call the GetUser function to fetch the user data from the database
	user, err := GetUser(db, current_id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Convert the user object to JSON and send it in the response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(user.ID)
}

// func GetCurrentUser(db *sql.DB) (*User, error) {
// 	query := "SELECT customer_id, firstname, email, password FROM oc_customer WHERE customer_id = 64274" // test
// 	row := db.QueryRow(query)

// 	user := &User{}
// 	err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return user, nil
// }

// func getAuthDiningHandler(w http.ResponseWriter, r *http.Request) {
// 	user_login := false
// 	customer_id := 0

// 	decoder := json.NewDecoder(r.Body)
// 	var t AuthResquestBody
// 	err := decoder.Decode(&t)
// 	if err != nil {
// 		panic(err)
// 	}

// 	if r.Method == http.MethodPost {
// 		secret_key := "abc"
// 		uid := t.Uid
// 		salt := t.Salt

// 		h := sha1.New()
// 		token := h.Sum([]byte(uid + salt + secret_key))

// 		if token == t.Token {
// 			customer_id = t.Uid
// 		} else {

// 			return
// 		}

// 		if customer_id > 0 {

// 		}

// 	}
// 	// Convert the user object to JSON and send it in the response
// 	w.Header().Set("Content-Type", "application/json")
// 	w.Header().Set("Access-Control-Allow-Origin", "*")

// 	json.NewEncoder(w).Encode(user_login)
// }
