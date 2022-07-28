package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/nats-io/nats.go"
)

type UserData struct {
	Login    string `json:"login" validate:"required,min=6,max=32,alphanum"`
	Password string `json:"password" validate:"required,min=6,max=32,alphanum"`
}

type Text string

type UserMessage struct {
	Message Text `json:"text" validate:"required"`
	UserID  int64
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("pgx", os.Getenv("AUTH_DB_URL"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	http.HandleFunc("/api/register", register)
	http.HandleFunc("/api/login", login)
	http.HandleFunc("/api/createMessage", createMessage)
	log.Fatal(http.ListenAndServe(":8000", nil))
}

// REST API user registration handler
func register(w http.ResponseWriter, r *http.Request) {
	user, err := readAuthResponse(r)
	if err != nil {
		log.Println(err)
		return
	}

	ifExists, err := checkLoginExists(user.Login)
	if err != nil {
		log.Println(err)
		return
	}

	v := validator.New()
	err = v.Struct(user)

	if err != nil {
		fmt.Fprintf(w, "Login and password can contain only Latin letters and numbers! Min length is 6, max len is 32")
		for _, e := range err.(validator.ValidationErrors) {
			log.Println(e)
		}
		return
	}

	if ifExists == true {
		fmt.Fprintf(w, "Login \"%s\" already exists!", user.Login)
		return
	}

	_, err = db.Exec("insert into auth_users (login, password) values ($1, $2)", user.Login, user.Password)
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Fprintf(w, "You have successfully registered as %s!", user.Login)
}

//REST API user authentification handler
func login(w http.ResponseWriter, r *http.Request) {
	user, err := readAuthResponse(r)
	if err != nil {
		log.Println(err)
		return
	}

	ifExists, err := checkLoginExists(user.Login)
	if err != nil {
		log.Println(err)
		return
	}

	if ifExists == false {
		fmt.Fprintf(w, "Login not found!")
		return
	}

	row := db.QueryRow("select password from auth_users where login = $1", user.Login)
	var expectedPassword string
	err = row.Scan(&expectedPassword)
	if err != nil {
		log.Println(err)
		return
	}

	if strings.Compare(user.Password, expectedPassword) == 0 {
		claims := &Claims{
			Username: user.Login,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_RESTAPI_KEY")))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "You've succesfully authorized!\nYour authorization token: %s", tokenString)
	} else {
		fmt.Fprintf(w, "Your password is not valid!")
	}
}

//REST API user message handler
func createMessage(w http.ResponseWriter, r *http.Request) {
	userToken := r.Header.Get("Authorization")

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(userToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_RESTAPI_KEY")), nil
	})
	if err != nil {
		log.Printf("User %s got error: %s", claims.Username, err)
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	userMsg, err := readMsgResponse(r)
	if err != nil {
		log.Println(err)
		return
	}

	v := validator.New()
	err = v.Struct(userMsg)

	if err != nil {
		fmt.Fprintf(w, "Text message can't be empty!")
		log.Println(err)
		return
	}

	userMsg.UserID, err = checkLoginID(claims.Username)

	log.Printf("%s (UserID %d) sent message: %s", claims.Username, userMsg.UserID, string(userMsg.Message))

	publishToNATS(userMsg)
}

//Multiply a struct of message data and sent it to NATS
func publishToNATS(userMsg UserMessage) {
	sliceOfMsg := make([]UserMessage, 0)
	for i := 0; i < 1000; i++ {
		sliceOfMsg = append(sliceOfMsg, userMsg)
	}

	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		panic(err)
	}
	defer nc.Close()

	ec, err := nats.NewEncodedConn(nc, nats.JSON_ENCODER)
	if err != nil {
		panic(err)
	}
	defer ec.Close()

	ec.Publish("nats_testing", sliceOfMsg)

	log.Printf("%d messages from UserID %d have been sent to NATS", len(sliceOfMsg), userMsg.UserID)
}

//Reads authentification data and returns it in a struct
func readAuthResponse(r *http.Request) (UserData, error) {
	var user UserData

	bs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return user, err
	}
	defer r.Body.Close()

	if err := json.Unmarshal(bs, &user); err != nil {
		log.Println(err)
		return user, err
	}

	return user, err
}

//Reads message data and returns it in a struct
func readMsgResponse(r *http.Request) (UserMessage, error) {
	var user UserMessage

	bs, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		return user, err
	}
	defer r.Body.Close()

	if err := json.Unmarshal(bs, &user); err != nil {
		log.Println(err)
		return user, err
	}

	return user, err
}

//Checks if login exists in DB
func checkLoginExists(login string) (bool, error) {
	row := db.QueryRow("select exists (select login, password from auth_users where login = $1)", login)
	var ifExists bool
	err := row.Scan(&ifExists)
	if err != nil {
		log.Println(err)
		return ifExists, err
	}

	return ifExists, err
}

//Checks the ID of login in DB
func checkLoginID(login string) (int64, error) {
	row := db.QueryRow("select id from auth_users where login = $1", login)
	var id int64
	err := row.Scan(&id)
	if err != nil {
		fmt.Println(err)
		return id, err
	}
	return id, err
}
