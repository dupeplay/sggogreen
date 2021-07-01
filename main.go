package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"

	"github.com/gin-gonic/gin"
)

var baseUrl = "http://localhost:3000/"
var userApiKey = "53f223e0-d827-11eb-b8bc-0242ac130003"
var db *sql.DB
var err error
var tpl *template.Template
var cookieHandler = securecookie.New(
	securecookie.GenerateRandomKey(64),
	securecookie.GenerateRandomKey(32))

type User struct {
	Email    string `form:"email" binding:"required"`
	Password string `form:"password" binding:"required"`
}

func getUserName(request *http.Request) (email string) {
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
			email = cookieValue["email"]
		}
	}
	return email
}
func setSession(email string, response http.ResponseWriter) {
	value := map[string]string{
		"email": email,
	}
	if encoded, err := cookieHandler.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}
func clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

// login handler

func checkLoginHandler(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	pass := request.FormValue("password")
	//fmt.Println(email)
	//fmt.Println(pass)

	redirectTarget := "/"
	if email != "" && pass != "" {
		u := User{email, pass}
		jsonReq, _ := json.Marshal(u)
		resp, err := http.Post(baseUrl+"login", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		// Convert response body to string
		//bodyString := string(bodyBytes)
		//	fmt.Println(bodyString)

		// Convert response body to Todo struct
		// var cr Cre
		// json.Unmarshal(bodyBytes, &todoStruct)
		// fmt.Printf("%+v\n", todoStruct)

		// Convert response body to Todo struct
		type userData struct {
			Id        int
			Email     string
			Password  string
			Role      string
			FirstName string
			LastName  string
			Location  string
		}
		type responseData struct {
			Code     int
			Message  string
			Status   string
			Response userData
		}

		//	U := userData{}
		ResponseData := responseData{}
		json.Unmarshal(bodyBytes, &ResponseData)
		fmt.Printf("%+v\n", ResponseData)
		if ResponseData.Status == "success" {
			setSession(email, response)
			redirectTarget = "/dashboard"
		} else {
			redirectTarget = "/errorPage"
		}

	}
	http.Redirect(response, request, redirectTarget, 302)
}

func logoutHandler(response http.ResponseWriter, request *http.Request) {
	clearSession(response)
	http.Redirect(response, request, "/index", 302)
}

type CreateSignUpRequest struct {
	Email      string `json:"email" form:"email"`
	Password   string `json:"password" form:"password"`
	FirstName  string `json:"firstName" form:"firstName"`
	LastName   string `json:"lastName" form:"lastName"`
	Location   string `json:"location" form:"location"`
	Phone      string `json:"phone" form:"phone"`
	DeviceCode string `json:"deviceCode" form:"deviceCode"`
}
type CreateHomeParameter struct {
	//UserID      string `json:"userID" form:"userID"`
	DeviceCode  string `json:"deviceCode" form:"deviceCode"`
	Temperature string `json:"temperature" form:"temperature"`
	// pressure    string `json:"pressure" form:"pressure"`
	Humidity string `json:"humidity" form:"humidity"`
}
type CreateDeviceUser struct {
	UserID   int `form:"userID" binding:"userID"`
	DeviceID int `form:"deviceID" binding:"deviceID	"`
}
type RequestHomeData struct {
	ApiKey string `form:"apiKey" binding:"required"`
	UserID int    `form:"userID" binding:"required"`
	Date   string `form:"date" binding:"required"`
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))

	db, err = sql.Open("mysql", "root:@tcp(localhost:3306)/gogreen")
	if err != nil {
		fmt.Println(err)
	}

	// defer the close till after the main function has finished
	// executing
	//defer db.Close()
	// if there is an error opening the connection, handle it
	err = db.Ping()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Db ok")
	}

}

var routeHandle = mux.NewRouter()

func main() {
	// Creates a gin router with default middleware:
	// logger and recovery (crash-free) middleware
	// routeHandle.HandleFunc("/", index)
	// routeHandle.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("public"))))
	// routeHandle.HandleFunc("/checkLogin", checkLoginHandler).Methods("POST")
	http.HandleFunc("/", index)
	http.HandleFunc("/dashboard", dashboard)
	http.HandleFunc("/checkLogin", checkLoginHandler)
	http.HandleFunc("/homeUserData", homeUserData)

	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("public"))))

	router := gin.Default()

	router.POST("/login", login)
	router.POST("/insertData", insertData)
	router.POST("/userList", userList)
	router.POST("/signup", Signup)
	router.POST("/homeData", HomeData)

	// // By default it serves on :8080 unless a
	// // PORT environment variable was defined.
	// router.Run()
	go func() {
		// http.Handle("/", routeHandle)
		http.ListenAndServe(":4000", nil)

	}()

	router.Run(":3000") //for a hard coded port

}
func login(c *gin.Context) {

	var loginUser User
	c.Bind(&loginUser) // This will infer what binder to use depending on the content-type header.

	rows, err := db.Query(`SELECT id, email, password, role,firstName, lastName, location from user where email = ?`, loginUser.Email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message":  err.Error(),
			"status":   "error",
			"code":     http.StatusOK,
			"response": loginUser,
		})
	}
	defer rows.Close()

	type u struct {
		Id        int
		Email     string
		Password  string
		Role      string
		FirstName string
		LastName  string
		Location  string
	}

	U := u{}

	for rows.Next() {

		err = rows.Scan(&U.Id, &U.Email, &U.Password, &U.Role, &U.FirstName, &U.LastName, &U.Location)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":  "unauthorized access",
				"status":   "error",
				"code":     http.StatusOK,
				"response": new(u),
			})
		}

	}

	if loginUser.Password == U.Password {

		c.JSON(http.StatusOK, gin.H{
			"message":  "you are logged in",
			"status":   "success",
			"code":     http.StatusOK,
			"response": U,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":  "unauthorized",
			"status":   "error",
			"code":     http.StatusOK,
			"response": new(u),
		})
	}

}
func insertData(c *gin.Context) {

	var homeParameter CreateHomeParameter
	c.Bind(&homeParameter)
	//fmt.Println(homeParameter.UserID, homeParameter.Temperature, homeParameter.Humidity)
	var DeviceID int
	err = db.QueryRow("SELECT id from device  WHERE deviceCode = ?", homeParameter.DeviceCode).Scan(&DeviceID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message":  err.Error(),
			"code":     http.StatusOK,
			"status":   "error",
			"response": homeParameter,
		})
		return
	} else {
		insert, err := db.Query("INSERT INTO `homeParameter` (`deviceID`, `temperature`, `humidity`) VALUES (?, ?, ?)", DeviceID, homeParameter.Temperature, homeParameter.Humidity)

		if err != nil {
			//fmt.Println(err)
			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
				"code":     http.StatusOK,
				"status":   "error",
				"response": homeParameter,
			})
		} else {

			c.JSON(http.StatusOK, gin.H{
				"message":  "Inserted",
				"code":     http.StatusOK,
				"status":   "success",
				"response": homeParameter,
			})
		}
		defer insert.Close()
	}
}

func Signup(c *gin.Context) {
	var signUpUser CreateSignUpRequest
	c.Bind(&signUpUser)
	//fmt.Println(homeParameter.UserID, homeParameter.Temperature, homeParameter.Humidity)
	insert, err := db.Query("INSERT INTO `user` (`email`, `password`,`firstName`, `lastName`, `location`, `phone`) VALUES (?, ?, ?,?,?,?)", signUpUser.Email, signUpUser.Password, signUpUser.FirstName, signUpUser.LastName, signUpUser.Location, signUpUser.Phone)

	if err != nil {
		//fmt.Println(err)
		c.JSON(http.StatusOK, gin.H{
			"message":  err.Error(),
			"code":     http.StatusOK,
			"status":   "error",
			"response": signUpUser,
		})
		return
	} else {

		rows, _ := db.Query("SELECT user.id, device.id from user, device WHERE user.email = ? AND device.deviceCode = ?", signUpUser.Email, signUpUser.DeviceCode)
		type userID struct {
			UserId   int
			DeviceId int
		}
		UserID := userID{}
		shouldinsert := false
		for rows.Next() {
			shouldinsert = true

			err = rows.Scan(&UserID.UserId, &UserID.DeviceId)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"message":  "Device not assigned",
					"status":   "error",
					"code":     http.StatusOK,
					"response": signUpUser,
				})
				return
			}

		}
		defer rows.Close()

		if !shouldinsert {
			c.JSON(http.StatusOK, gin.H{
				"message":  "Device not assigned",
				"status":   "error",
				"code":     http.StatusOK,
				"response": signUpUser,
			})
			return
		}
		// type DeviceToUser struct {

		// 	Id    int
		// 	userID int
		// }
		var DeviceToUserID int
		err = db.QueryRow("SELECT id from device_to_user  WHERE deviceID = ?", UserID.DeviceId).Scan(&DeviceToUserID)

		if err != nil {
			insert, err := db.Query("INSERT INTO `device_to_user` (`userID`, `deviceID`) VALUES (?, ?)", UserID.UserId, UserID.DeviceId)

			if err != nil {
				//fmt.Println(err)
				c.JSON(http.StatusOK, gin.H{
					"message":  err.Error(),
					"code":     http.StatusOK,
					"status":   "error",
					"response": signUpUser,
				})
				return
			} else {

			}
			defer insert.Close()
		} else {
			if DeviceToUserID == 0 {
				insert, err := db.Query("INSERT INTO `device_to_user` (`userID`, `deviceID`) VALUES (?, ?)", UserID.UserId, UserID.DeviceId)

				if err != nil {
					//fmt.Println(err)
					c.JSON(http.StatusOK, gin.H{
						"message":  err.Error(),
						"code":     http.StatusOK,
						"status":   "error55",
						"response": signUpUser,
					})
					return
				} else {

				}
				defer insert.Close()

			} else {
				c.JSON(http.StatusOK, gin.H{
					"message":  "Device already linked. Pleease contact admin",
					"code":     http.StatusOK,
					"status":   "error66",
					"response": signUpUser,
				})
				return
			}

		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "Inserted",
			"code":     http.StatusOK,
			"status":   "success",
			"response": signUpUser,
		})
	}
	defer insert.Close()

}
func userList(c *gin.Context) {
	type UserData struct {
		Id         int
		Email      string
		Role       string
		FirstName  string
		LastName   string
		Location   string
		Phone      string
		DeviceID   sql.NullInt32
		DeviceName sql.NullString
		DeviceCode sql.NullString
	}

	UserDataList := []UserData{}

	// var loginUser User
	// c.Bind(&loginUser) // This will infer what binder to use depending on the content-type header.

	rows, err := db.Query(`SELECT user.id, user.email, user.role, user.firstName, user.lastName, user.location, user.phone,
	device_to_user.deviceID, device.name, device.deviceCode
	FROM user
	
	LEFT JOIN device_to_user ON device_to_user.userID = user.id
	LEFT JOIN device ON device.id = device_to_user.id
	
	WHERE user.role = 'user'`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message":  "server error",
			"status":   "error",
			"code":     http.StatusOK,
			"response": UserDataList,
		})
		return
	}
	defer rows.Close()

	for rows.Next() {
		data := UserData{}
		err = rows.Scan(&data.Id, &data.Email, &data.Role, &data.FirstName, &data.LastName, &data.Location, &data.Phone,
			&data.DeviceID, &data.DeviceName, &data.DeviceCode)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
				"status":   "error",
				"code":     http.StatusOK,
				"response": new(UserData),
			})
			return
		}
		UserDataList = append(UserDataList, data)

	}
	c.JSON(http.StatusOK, gin.H{
		"message":  "Successfully fetched",
		"status":   "success",
		"code":     http.StatusOK,
		"response": UserDataList,
	})

}

func HomeData(c *gin.Context) {
	var requestHomeData RequestHomeData
	var deviceID int
	c.Bind(&requestHomeData)
	fmt.Println(requestHomeData)
	if requestHomeData.ApiKey == userApiKey {
		err = db.QueryRow("SELECT deviceID  from device_to_user  WHERE userid = ?", requestHomeData.UserID).Scan(&deviceID)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
				"code":     http.StatusOK,
				"status":   "error",
				"response": requestHomeData,
			})

		} else {

			type Parameter struct {
				Id          int
				DeviceID    string
				Temperature string
				Humidity    string
				Create_at   string
			}

			ParameterList := []Parameter{}
			var rows *sql.Rows
			// var loginUser User
			// c.Bind(&loginUser) // This will infer what binder to use depending on the content-type header.
			if requestHomeData.Date != "" {
				rows, err = db.Query(`SELECT homeParameter.id, homeParameter.deviceID, homeParameter.temperature, homeParameter.humidity, 
				homeParameter.create_at from homeParameter WHERE homeParameter.deviceID = ? 
				and homeParameter.create_at  Like ?`, deviceID, requestHomeData.Date+"%")

			} else {
				rows, err = db.Query(`SELECT homeParameter.id, homeParameter.deviceID, homeParameter.temperature, homeParameter.humidity, 
				homeParameter.create_at from homeParameter WHERE homeParameter.deviceID = ?`, deviceID)

			}
			// rows, err := db.Query(`SELECT homeParameter.id, homeParameter.deviceID, homeParameter.temperature, homeParameter.humidity,
			// homeParameter.create_at from homeParameter WHERE homeParameter.deviceID = ?`, deviceID)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"message":  "server error",
					"status":   "error",
					"code":     http.StatusOK,
					"response": ParameterList,
				})
				return
			}
			defer rows.Close()

			for rows.Next() {
				data := Parameter{}
				err = rows.Scan(&data.Id, &data.DeviceID, &data.Temperature, &data.Humidity, &data.Create_at)
				if err != nil {
					c.JSON(http.StatusOK, gin.H{
						"message":  err.Error(),
						"status":   "error",
						"code":     http.StatusOK,
						"response": ParameterList,
					})
					return
				}
				ParameterList = append(ParameterList, data)

			}
			c.JSON(http.StatusOK, gin.H{
				"message":  "Successfully fetched",
				"status":   "success",
				"code":     http.StatusOK,
				"response": ParameterList,
			})

		}

	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Unautherized Access",
			"status":   "error",
			"code":     http.StatusOK,
			"response": requestHomeData,
		})
	}

}

// func test(c *gin.Context) {
// 	c.JSON(200, gin.H{
// 		"message": "hello world",
// 	})
// }

/* Http handlers */

func index(res http.ResponseWriter, req *http.Request) {
	err := tpl.ExecuteTemplate(res, "login.gohtml", nil)
	if err != nil {
		log.Fatalln("template didn't execute: ", err)
	}
}

func dashboard(res http.ResponseWriter, req *http.Request) {
	//err := tpl.ExecuteTemplate(res, "dashboard.gohtml", nil)

	if err != nil {
		log.Fatalln("template didn't execute: ", err)
	}
	type Api struct {
		ApiKey string
	}
	a := Api{userApiKey}
	jsonReq, _ := json.Marshal(a)
	resp, err := http.Post(baseUrl+"userList", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	type Did struct {
		Int32 int
		Valid bool
	}
	type DName struct {
		String string
		Valid  bool
	}
	type DCode struct {
		String string
		Valid  bool
	}
	type userData struct {
		Id         int
		Email      string
		Role       string
		FirstName  string
		LastName   string
		Location   string
		Phone      string
		DeviceID   Did
		DeviceName DName
		DeviceCode DCode
	}
	type responseData struct {
		Code     int
		Message  string
		Status   string
		Response []userData
	}

	//	U := userData{}
	ResponseData := responseData{}
	json.Unmarshal(bodyBytes, &ResponseData)
	//fmt.Printf("%+v\n", ResponseData)
	if ResponseData.Status == "success" {
		//	err := tplAdmin.ExecuteTemplate(res, "listbooking.gohtml", UserList)
		if err != nil {
			log.Fatalln("template didn't execute: ", err)
		}

		err = tpl.ExecuteTemplate(res, "dashboard.gohtml", ResponseData.Response)

		if err != nil {
			log.Fatalln(err)
		}
	} else {
		err = tpl.ExecuteTemplate(res, "dashboard.gohtml", nil)

		//	fmt.Println(ResponseData.Response[0].Id)
		if err != nil {
			log.Fatalln(err)
		}
	}

}

func homeUserData(res http.ResponseWriter, req *http.Request) {

	userID := req.FormValue("userId")

	type Api struct {
		ApiKey string
		UserID int
	}
	fmt.Println(userID)
	i, _ := strconv.Atoi(userID)
	a := Api{userApiKey, i}

	jsonReq, _ := json.Marshal(a)
	resp, err := http.Post(baseUrl+"homeData", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	type userData struct {
		Id          int
		DeviceID    string
		Temperature string
		Humidity    string
		Create_at   string
	}
	type responseData struct {
		Code     int
		Message  string
		Status   string
		Response []userData
	}

	//	U := userData{}
	ResponseData := responseData{}
	json.Unmarshal(bodyBytes, &ResponseData)
	fmt.Printf("%+v\n", ResponseData)
	if ResponseData.Status == "success" {
		//	err := tplAdmin.ExecuteTemplate(res, "listbooking.gohtml", UserList)
		if err != nil {
			log.Fatalln("template didn't execute: ", err)
		}

		err = tpl.ExecuteTemplate(res, "homedata.gohtml", ResponseData.Response)

		if err != nil {
			log.Fatalln(err)
		}
	} else {
		err = tpl.ExecuteTemplate(res, "homedata.gohtml", nil)

		//	fmt.Println(ResponseData.Response[0].Id)
		if err != nil {
			log.Fatalln(err)
		}
	}

}
