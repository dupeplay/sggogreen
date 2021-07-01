package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math"
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
var rows *sql.Rows
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
type RequestDashboardDetail struct {
	ApiKey string `form:"apiKey" binding:"required"`
	UserID int    `form:"userID" binding:"required"`
	//Location string `form:"location" binding:"required"`

	//Date   string `form:"date" binding:"required"`
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))

	db, err = sql.Open("mysql", "root:root@tcp(localhost:3307)/gogreen")
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
	http.HandleFunc("/users", users)
	http.HandleFunc("/devices", deviceDataHandle)
	http.HandleFunc("/adduser", addUser)
	http.HandleFunc("/edituserui", edituserui)
	http.HandleFunc("/edituserlogic", edituserlogic)

	http.HandleFunc("/saveUser", saveUser)
	http.HandleFunc("/adddeviceui", adddeviceui)
	http.HandleFunc("/savedevice", savedevice)
	http.HandleFunc("/deleteuser", deleteuser)

	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("public"))))

	router := gin.Default()

	router.POST("/login", login)
	router.POST("/insertData", insertData)
	router.POST("/userList", userList)
	router.POST("/signup", Signup)
	router.POST("/homeData", HomeData)
	router.POST("/getAdmin", GetAdmin)
	router.POST("/device", device)
	router.POST("/edituser", edituser)
	router.POST("/adddevice", adddevice)

	router.POST("/dashboardDetail", DashboardDetail)

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
			"message":  "server error" + err.Error(),
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

	var requestDashboardDetail RequestDashboardDetail
	c.Bind((&requestDashboardDetail))
	if requestDashboardDetail.ApiKey == userApiKey {
		//var openWeather = "api.openweathermap.org/data/2.5/weather?q={city name}&appid={API key}"

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
		if requestDashboardDetail.UserID == 1 {
			rows, err = db.Query(`SELECT user.id, user.email, user.role, user.firstName, user.lastName, user.location, user.phone,
			device_to_user.deviceID, device.name, device.deviceCode
			FROM user
			
			LEFT JOIN device_to_user ON device_to_user.userID = user.id
			LEFT JOIN device ON device.id = device_to_user.deviceID
			
			WHERE user.role = 'user'`)
		} else {
			rows, err = db.Query(`SELECT user.id, user.email, user.role, user.firstName, user.lastName, user.location, user.phone,
				device_to_user.deviceID, device.name, device.deviceCode
				FROM user
				
				LEFT JOIN device_to_user ON device_to_user.userID = user.id
				LEFT JOIN device ON device.id = device_to_user.deviceID
				
				WHERE user.role = 'user' and user.id = ?`, requestDashboardDetail.UserID)
		}

		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
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

	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Unauthorised Access",
			"code":     http.StatusOK,
			"status":   "error",
			"response": requestDashboardDetail,
		})
	}

}

func device(c *gin.Context) {
	var requestDashboardDetail RequestDashboardDetail
	c.Bind((&requestDashboardDetail))
	if requestDashboardDetail.ApiKey == userApiKey {
		//var openWeather = "api.openweathermap.org/data/2.5/weather?q={city name}&appid={API key}"

		type deviceData struct {
			Id         int
			Name       string
			DeviceCode string
			Status     string
		}

		DeviceList := []deviceData{}

		// var loginUser User
		// c.Bind(&loginUser) // This will infer what binder to use depending on the content-type header.

		rows, err = db.Query(`SELECT * from device`)

		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
				"status":   "error",
				"code":     http.StatusOK,
				"response": DeviceList,
			})
			return
		}
		defer rows.Close()

		for rows.Next() {
			data := deviceData{}
			err = rows.Scan(&data.Id, &data.Name, &data.DeviceCode, &data.Status)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"message":  err.Error(),
					"status":   "error",
					"code":     http.StatusOK,
					"response": new(deviceData),
				})
				return
			}
			DeviceList = append(DeviceList, data)

		}
		c.JSON(http.StatusOK, gin.H{
			"message":  "Successfully fetched",
			"status":   "success",
			"code":     http.StatusOK,
			"response": DeviceList,
		})

	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Unauthorised Access",
			"code":     http.StatusOK,
			"status":   "error",
			"response": requestDashboardDetail,
		})
	}

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

func getDashboard(c *gin.Context) {
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

func DashboardDetail(c *gin.Context) {

	var requestDashboardDetail RequestDashboardDetail
	c.Bind((&requestDashboardDetail))
	fmt.Println("usrID", requestDashboardDetail.UserID)
	if requestDashboardDetail.ApiKey == userApiKey {
		var openWeather = ""
		var totalUser = 0
		var deviceID = 0
		var location = ""
		var humidity float64
		var temperature float64
		if requestDashboardDetail.UserID == 1 {

			openWeather = "https://api.openweathermap.org/data/2.5/weather?q=singapore&appid=e7a0d1c0f1dd21c7d7ec88f12be1d897&units=imperial"

			err = db.QueryRow("SELECT count(user.id) from user where user.role='user'").Scan(&totalUser)

			if err != nil {

				totalUser = 0

			}
			fmt.Println("totalUser ", totalUser)
		} else {
			err = db.QueryRow("SELECT location, (SELECT device_to_user.deviceID from device_to_user where device_to_user.userID = ?)deviceID from user where user.id=?", requestDashboardDetail.UserID, requestDashboardDetail.UserID).Scan(&location, &deviceID)
			if err != nil {
				log.Fatalln(err)
			}
			if location == "Woodlands11" || location == "woodlands11" {
				openWeather = "http://api.openweathermap.org/data/2.5/find?lat=1.4414267&lon=103.7532869&cnt=5&appid=e7a0d1c0f1dd21c7d7ec88f12be1d897"
			} else if location == "Bukit Batok1" || location == "Bukit bato1k" {
				openWeather = "http://api.openweathermap.org/data/2.5/find?lat=1.3560767&lon=103.7446868&cnt=5&appid=e7a0d1c0f1dd21c7d7ec88f12be1d897"

			} else {
				openWeather = "https://api.openweathermap.org/data/2.5/weather?q=" + location + "&appid=e7a0d1c0f1dd21c7d7ec88f12be1d897&units=imperial"
			}
			//err = db.QueryRow("SELECT count(user.id) from user where user.role='user'").Scan(&totalUser)
			err = db.QueryRow("select  homeParameter.temperature, homeParameter.humidity FROM homeParameter WHERE homeParameter.deviceID = ? order by id DESC limit 1", deviceID).Scan(&temperature, &humidity)
			if err != nil {
				temperature = 0.0
				humidity = 0.0
			} else {
				fmt.Println("feteched celcius temperature-", temperature, "feteched humidty -", humidity)
				temperature = (temperature * 1.8) + 32
				fmt.Println("feteched farenheit temperature-", temperature, "feteched humidty -", humidity)
				//temperature = 73.004
				//humidity = 61
			}
		}

		resp, err := http.Get(openWeather)
		if err != nil {
			log.Fatalln(err)
		}
		defer resp.Body.Close()
		bodyBytes, _ := ioutil.ReadAll(resp.Body)

		type mainData struct {
			Temp       float64
			Feels_like float64
			Temp_min   float64
			Temp_max   float64
			Pressure   int
			Humidity   float64
			Msg        string
			HI         float64
			UserCount  int
			Optimal    float64
			RoomTemp   float64
			RoomHum    float64
		}
		type responseData struct {
			Main mainData
		}

		//	U := userData{}

		ResponseData := responseData{}
		json.Unmarshal(bodyBytes, &ResponseData)
		fmt.Printf("%+v\n", ResponseData)
		ResponseData.Main.RoomHum = humidity
		ResponseData.Main.RoomTemp = temperature
		ResponseData.Main.RoomTemp = (ResponseData.Main.RoomTemp - 32) * 0.555
		ResponseData.Main.RoomTemp = (math.Round(ResponseData.Main.RoomTemp * 100)) / 100

		ResponseData.Main.UserCount = totalUser
		fmt.Println("Temperature -", temperature, "Humidit - ", humidity)

		if temperature > 0 {

			var T = temperature
			var R = humidity
			fmt.Println("Temperature -", T, "Humidit - ", R)

			var c1 = -42.379
			var c2 = 2.04901523
			var c3 = 10.14333127
			var c4 = -0.22475541
			var c5 = -6.83783 * 0.001 // / (10 * 10 * 10)
			var c6 = -5.481717 * 0.01
			var c7 = 1.22874 * 0.001  // / (10 * 10 * 10)
			var c8 = 8.5282 * 0.0001  /// (10 * 10 * 10 * 10)
			var c9 = -1.99 * 0.000001 /// (10 * 10 * 10 * 10 * 10 * 10)
			//Heat Index (HI) = c1 + c2T + c3R + c4TR + c5T2 + c6R2+c7T2R+c8TR2+ c9T2R2
			HI := c1 + (c2 * T) + (c3 * R) + (c4 * T * R) + (c5 * T * T) + (c6 * R * R) + (c7 * T * T * R) + (c8 * T * R * R) + (c9 * T * T * R * R)
			// HI := c1 + c2*T + c3*R + c4*T*R + c5*T*T + c6*R*R + c7*T*T*R + c8*T*R*R + c9*T*T*R*R
			fmt.Println("Heat index -", HI)

			HI = (math.Round(HI * 100)) / 100
			fmt.Println("Heat index Rounded -", HI)
			ResponseData.Main.HI = HI

			if T == HI {
				ResponseData.Main.Optimal = T
			} else {
				for i := T - 1; i >= 0; i = i - .15 {
					HI = c1 + c2*i + c3*R + c4*i*R + c5*i*i + c6*i*i + c7*i*i*R + c8*i*R*R + c9*i*i*R*R
					if math.Round(HI) >= math.Round(i) {
						ResponseData.Main.Optimal = i
						break
					}
				}
			}
			if ResponseData.Main.Optimal == 0 {
				ResponseData.Main.Optimal = ResponseData.Main.Feels_like
			}
			var msg = ""
			if HI > 80 && HI <= 90 {
				msg = "Caution:  Fatigue is possible with prolonged exposure and activity"
			} else if HI > 90 && HI <= 105 {
				msg = "Extreme Caution:  Sunstroke, heat cramps, and heat exhaustion are possible"

			} else if HI > 105 && HI <= 130 {
				msg = "Danger:  Sunstroke, heat cramps, and heat exhaustion likely; Heat stroke is possible"

			} else if HI > 130 {
				msg = "Extreme Danger:  Heat stroke or sunstroke likely with continued exposure"

			}
			ResponseData.Main.Msg = msg
			//ResponseData.Main.Feels_like = HI
			ResponseData.Main.UserCount = totalUser

			//fmt.Println(msg)
			ResponseData.Main.Temp = temperature
			ResponseData.Main.Temp = humidity
		}
		ResponseData.Main.Temp = (ResponseData.Main.Temp - 32) * 0.555
		ResponseData.Main.Temp = (math.Round(ResponseData.Main.Temp * 100)) / 100

		ResponseData.Main.HI = (ResponseData.Main.HI - 32) * 0.555
		ResponseData.Main.HI = (math.Round(ResponseData.Main.HI * 100)) / 100

		ResponseData.Main.Feels_like = (ResponseData.Main.Feels_like - 32) * 0.555
		ResponseData.Main.Feels_like = (math.Round(ResponseData.Main.Feels_like * 100)) / 100

		ResponseData.Main.Optimal = (ResponseData.Main.Optimal - 32) * 0.555
		ResponseData.Main.Optimal = (math.Round(ResponseData.Main.Optimal * 100)) / 100
		c.JSON(http.StatusOK, gin.H{
			"message": "Feteched Successfully",
			"code":    http.StatusOK,
			"status":  "sucess",
			"response": mainData{
				ResponseData.Main.Temp,
				ResponseData.Main.Feels_like,
				ResponseData.Main.Temp_min,
				ResponseData.Main.Temp_max,
				ResponseData.Main.Pressure,
				ResponseData.Main.Humidity,
				ResponseData.Main.Msg,
				ResponseData.Main.HI,
				ResponseData.Main.UserCount,
				ResponseData.Main.Optimal,
				ResponseData.Main.RoomTemp,
				ResponseData.Main.RoomHum,
			},
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Unauthorised Access",
			"code":     http.StatusOK,
			"status":   "error",
			"response": requestDashboardDetail,
		})
	}
}

func GetAdmin(c *gin.Context) {
	var requestHomeData RequestHomeData
	//var deviceID int
	var totalUser int
	var avgTemp float32
	var avgHumidity float32
	c.Bind(&requestHomeData)
	fmt.Println(requestHomeData)
	if requestHomeData.ApiKey == userApiKey {
		err = db.QueryRow("select (SELECT count(user.id) from user where user.role='user') as totalUser, ROUND(AVG(temperature),2) temperature, Round(AVG(humidity),2)humidity from homeParameter").Scan(&totalUser, &avgTemp, &avgHumidity)
		fmt.Println(totalUser, avgTemp, avgHumidity)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
				"code":     http.StatusOK,
				"status":   "error",
				"response": requestHomeData,
			})

		} else {

			type dashboard struct {
				TotalUser int
				//	DeviceID    float32
				Temperature float32
				Humidity    float32
				//Create_at   string
			}

			DashboardList := dashboard{}
			DashboardList.Humidity = avgHumidity
			DashboardList.Temperature = avgTemp
			DashboardList.TotalUser = totalUser
			// var rows *sql.Rows
			// // var loginUser User
			// // c.Bind(&loginUser) // This will infer what binder to use depending on the content-type header.
			// if requestHomeData.Date != "" {
			// 	rows, err = db.Query(`SELECT homeParameter.id, homeParameter.deviceID, homeParameter.temperature, homeParameter.humidity,
			// 	homeParameter.create_at from homeParameter WHERE homeParameter.deviceID = ?
			// 	and homeParameter.create_at  Like ?`, deviceID, requestHomeData.Date+"%")

			// } else {
			// 	rows, err = db.Query(`SELECT homeParameter.id, homeParameter.deviceID, homeParameter.temperature, homeParameter.humidity,
			// 	homeParameter.create_at from homeParameter WHERE homeParameter.deviceID = ?`, deviceID)

			// }
			// // rows, err := db.Query(`SELECT homeParameter.id, homeParameter.deviceID, homeParameter.temperature, homeParameter.humidity,
			// // homeParameter.create_at from homeParameter WHERE homeParameter.deviceID = ?`, deviceID)
			// if err != nil {
			// 	c.JSON(http.StatusOK, gin.H{
			// 		"message":  "server error",
			// 		"status":   "error",
			// 		"code":     http.StatusOK,
			// 		"response": ParameterList,
			// 	})
			// 	return
			// }
			// defer rows.Close()

			// for rows.Next() {
			// 	data := Parameter{}
			// 	err = rows.Scan(&data.Id, &data.DeviceID, &data.Temperature, &data.Humidity, &data.Create_at)
			// 	if err != nil {
			// 		c.JSON(http.StatusOK, gin.H{
			// 			"message":  err.Error(),
			// 			"status":   "error",
			// 			"code":     http.StatusOK,
			// 			"response": ParameterList,
			// 		})
			// 		return
			// 	}
			// 	ParameterList = append(ParameterList, data)

			// }
			c.JSON(http.StatusOK, gin.H{
				"message":  "Successfully fetched",
				"status":   "success",
				"code":     http.StatusOK,
				"response": DashboardList,
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

	type Api struct {
		ApiKey string
		UserID int
	}
	a := Api{userApiKey, 1}
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
	fmt.Println("hii")
	fmt.Println(jsonReq)
	resp, err = http.Post(baseUrl+"dashboardDetail", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)

	type mainData struct {
		Temp       float64
		Feels_like float64
		Temp_min   float64
		Temp_max   float64
		Pressure   int
		Humidity   float64
		Msg        string
		HI         float64
		UserCount  int
	}
	type MainResponseData struct {
		Code     int
		Message  string
		Status   string
		Response mainData
	}

	//	U := userData{}
	MainResponse := MainResponseData{}
	json.Unmarshal(bodyBytes, &MainResponse)

	fmt.Printf("%+v\n", MainResponse.Response)

	resp, err = http.Post(baseUrl+"device", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)

	type DeviceData struct {
		Id         float64
		Name       string
		DeviceCode string
		Status     string
	}
	type ResponseDeviceData struct {
		Code     int
		Message  string
		Status   string
		Response []DeviceData
	}

	//	U := userData{}
	DeviceResponseDeviceData := ResponseDeviceData{}
	json.Unmarshal(bodyBytes, &DeviceResponseDeviceData)

	fmt.Printf("%+v\n", DeviceResponseDeviceData.Response)

	type items struct {
		Widget   mainData
		UserList []userData
		Device   []DeviceData
	}
	data := items{
		Widget:   MainResponse.Response,
		UserList: ResponseData.Response,
		Device:   DeviceResponseDeviceData.Response,
	}
	if ResponseData.Status == "success" {
		//	err := tplAdmin.ExecuteTemplate(res, "listbooking.gohtml", UserList)
		if err != nil {
			log.Fatalln("template didn't execute: ", err)
		}

		err = tpl.ExecuteTemplate(res, "dashboard.gohtml", data)

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

	resp, err = http.Post(baseUrl+"dashboardDetail", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)

	type mainData struct {
		Temp       float64
		Feels_like float64
		Temp_min   float64
		Temp_max   float64
		Pressure   int
		Humidity   float64
		Msg        string
		HI         float64
		UserCount  int
		Optimal    float64
	}
	type MainResponseData struct {
		Code     int
		Message  string
		Status   string
		Response mainData
	}

	//	U := userData{}
	MainResponse := MainResponseData{}
	json.Unmarshal(bodyBytes, &MainResponse)

	fmt.Printf("%+v\n", MainResponse.Response)

	resp, err = http.Post(baseUrl+"userList", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)
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
	type userInfoData struct {
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
	type userResponseData struct {
		Code     int
		Message  string
		Status   string
		Response []userInfoData
	}

	//	U := userData{}
	UserResponseData := userResponseData{}
	json.Unmarshal(bodyBytes, &UserResponseData)

	type items struct {
		Widget   mainData
		UserList []userData
		UserInfo []userInfoData
	}
	data := items{
		Widget:   MainResponse.Response,
		UserList: ResponseData.Response,
		UserInfo: UserResponseData.Response,
	}
	fmt.Printf("%+v\n", UserResponseData.Response)

	if ResponseData.Status == "success" {
		//	err := tplAdmin.ExecuteTemplate(res, "listbooking.gohtml", UserList)
		if err != nil {
			log.Fatalln("template didn't execute: ", err)
		}

		err = tpl.ExecuteTemplate(res, "homedata.gohtml", data)

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

func users(res http.ResponseWriter, req *http.Request) {
	//err := tpl.ExecuteTemplate(res, "dashboard.gohtml", nil)

	type Api struct {
		ApiKey string
		UserID int
	}
	a := Api{userApiKey, 1}
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
	fmt.Println("hii")
	fmt.Println(jsonReq)
	resp, err = http.Post(baseUrl+"dashboardDetail", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)

	type mainData struct {
		Temp       float64
		Feels_like float64
		Temp_min   float64
		Temp_max   float64
		Pressure   int
		Humidity   float64
		Msg        string
		HI         float64
		UserCount  int
	}
	type MainResponseData struct {
		Code     int
		Message  string
		Status   string
		Response mainData
	}

	//	U := userData{}
	MainResponse := MainResponseData{}
	json.Unmarshal(bodyBytes, &MainResponse)

	fmt.Printf("%+v\n", MainResponse.Response)
	type items struct {
		Widget   mainData
		UserList []userData
	}
	data := items{
		Widget:   MainResponse.Response,
		UserList: ResponseData.Response,
	}
	if ResponseData.Status == "success" {
		//	err := tplAdmin.ExecuteTemplate(res, "listbooking.gohtml", UserList)
		if err != nil {
			log.Fatalln("template didn't execute: ", err)
		}

		err = tpl.ExecuteTemplate(res, "userList.gohtml", data)

		if err != nil {
			log.Fatalln(err)
		}
	} else {
		err = tpl.ExecuteTemplate(res, "userList.gohtml", nil)

		//	fmt.Println(ResponseData.Response[0].Id)
		if err != nil {
			log.Fatalln(err)
		}
	}

}

func deviceDataHandle(res http.ResponseWriter, req *http.Request) {
	//err := tpl.ExecuteTemplate(res, "dashboard.gohtml", nil)

	type Api struct {
		ApiKey string
		UserID int
	}
	a := Api{userApiKey, 1}
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
	fmt.Println("hii")
	fmt.Println(jsonReq)
	resp, err = http.Post(baseUrl+"dashboardDetail", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)

	type mainData struct {
		Temp       float64
		Feels_like float64
		Temp_min   float64
		Temp_max   float64
		Pressure   int
		Humidity   float64
		Msg        string
		HI         float64
		UserCount  int
	}
	type MainResponseData struct {
		Code     int
		Message  string
		Status   string
		Response mainData
	}

	//	U := userData{}
	MainResponse := MainResponseData{}
	json.Unmarshal(bodyBytes, &MainResponse)

	fmt.Printf("%+v\n", MainResponse.Response)

	resp, err = http.Post(baseUrl+"device", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	bodyBytes, _ = ioutil.ReadAll(resp.Body)

	type DeviceData struct {
		Id         float64
		Name       string
		DeviceCode string
		Status     string
	}
	type ResponseDeviceData struct {
		Code     int
		Message  string
		Status   string
		Response []DeviceData
	}

	//	U := userData{}
	DeviceResponseDeviceData := ResponseDeviceData{}
	json.Unmarshal(bodyBytes, &DeviceResponseDeviceData)

	fmt.Printf("%+v\n", DeviceResponseDeviceData.Response)

	type items struct {
		Widget   mainData
		UserList []userData
		Device   []DeviceData
	}
	data := items{
		Widget:   MainResponse.Response,
		UserList: ResponseData.Response,
		Device:   DeviceResponseDeviceData.Response,
	}
	if ResponseData.Status == "success" {
		//	err := tplAdmin.ExecuteTemplate(res, "listbooking.gohtml", UserList)
		if err != nil {
			log.Fatalln("template didn't execute: ", err)
		}

		err = tpl.ExecuteTemplate(res, "device.gohtml", data)

		if err != nil {
			log.Fatalln(err)
		}
	} else {
		err = tpl.ExecuteTemplate(res, "device.gohtml", nil)

		//	fmt.Println(ResponseData.Response[0].Id)
		if err != nil {
			log.Fatalln(err)
		}
	}

}

func addUser(res http.ResponseWriter, req *http.Request) {

	err := tpl.ExecuteTemplate(res, "adduser.gohtml", nil)
	if err != nil {
		log.Fatalln("template didn't execute: ", err)
	}

}
func saveUser(response http.ResponseWriter, request *http.Request) {
	email := request.FormValue("email")
	pass := request.FormValue("password")
	firstName := request.FormValue("first")
	lastName := request.FormValue("last")
	location := request.FormValue("location")
	deviceCode := request.FormValue("device")

	type User struct {
		Email      string
		Password   string
		FirstName  string
		LastName   string
		Location   string
		Phone      string
		DeviceCode string
	}
	a := User{email, pass, firstName, lastName, location, "", deviceCode}
	jsonReq, _ := json.Marshal(a)
	resp, err := http.Post(baseUrl+"signup", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	http.Redirect(response, request, "/users", http.StatusFound)

}

type RequestEditData struct {
	Email     string `json:"email" form:"email"`
	Password  string `json:"password" form:"password"`
	FirstName string `json:"firstName" form:"firstName"`
	LastName  string `json:"lastName" form:"lastName"`
	Location  string `json:"location" form:"location"`
	UserID    string `json:"userID" form:"userID"`
	//	DeviceCode string `json:"deviceCode" form:"deviceCode"`
	ApiKey string `json:"apiKey" form:"apiKey"`
}

func edituser(c *gin.Context) {
	var requestEditData RequestEditData
	var userID = 0
	c.Bind(&requestEditData)
	fmt.Println(requestEditData)
	if requestEditData.ApiKey == userApiKey {
		fmt.Println("user id - ", requestEditData.UserID)
		err = db.QueryRow("select id  FROM user WHERE id= ? ", requestEditData.UserID).Scan(&userID)
		fmt.Println("22")
		if err != nil {
			userID = 0
		} else {
			fmt.Println("hii")
			update, err := db.Query("update user set email=?, password=?, firstName=?, lastName=?, location=? WHERE id= ? ", requestEditData.Email, requestEditData.Password, requestEditData.FirstName, requestEditData.LastName, requestEditData.Location, requestEditData.UserID)
			update.Close()
			if err != nil {

				c.JSON(http.StatusOK, gin.H{
					"message":  err.Error(),
					"status":   "success",
					"code":     http.StatusOK,
					"response": requestEditData,
				})
			} else {
				c.JSON(http.StatusOK, gin.H{
					"message":  "Successfully Updated",
					"status":   "success",
					"code":     http.StatusOK,
					"response": requestEditData,
				})
			}
		}

	}
}
func edituserui(res http.ResponseWriter, req *http.Request) {
	userID := req.FormValue("userEditId")

	err := tpl.ExecuteTemplate(res, "edituserui.gohtml", userID)
	if err != nil {
		log.Fatalln("template didn't execute: ", err)
	}

}
func edituserlogic(res http.ResponseWriter, req *http.Request) {

	email := req.FormValue("email")
	pass := req.FormValue("password")
	firstName := req.FormValue("first")
	lastName := req.FormValue("last")
	location := req.FormValue("location")
	userID := req.FormValue("userID")
	fmt.Println("first")

	type User struct {
		Email     string
		Password  string
		FirstName string
		LastName  string
		Location  string
		Phone     string
		UserID    string
		ApiKey    string
	}
	a := User{email, pass, firstName, lastName, location, "", userID, userApiKey}
	jsonReq, _ := json.Marshal(a)
	fmt.Println("heww")
	fmt.Println(jsonReq)
	resp, err := http.Post(baseUrl+"edituser", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("hereee")
	defer resp.Body.Close()
	http.Redirect(res, req, "/users", http.StatusFound)

}

type RequestAddDevice struct {
	Name       string `json:"name" form:"name"`
	DeviceCode string `json:"deviceCode" form:"deviceCode"`

	ApiKey string `json:"apiKey" form:"apiKey"`
}

func adddevice(c *gin.Context) {
	var requestAddDevice RequestAddDevice

	c.Bind(&requestAddDevice)
	fmt.Println(requestAddDevice)
	if requestAddDevice.ApiKey == userApiKey {

		insert, err := db.Query("INSERT INTO `device` (`name`, `deviceCode`) VALUES (?, ?)", requestAddDevice.Name, requestAddDevice.DeviceCode)

		insert.Close()
		if err != nil {

			c.JSON(http.StatusOK, gin.H{
				"message":  err.Error(),
				"status":   "success",
				"code":     http.StatusOK,
				"response": requestAddDevice,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"message":  "Successfully Added",
				"status":   "success",
				"code":     http.StatusOK,
				"response": requestAddDevice,
			})
		}

	}
	c.JSON(http.StatusOK, gin.H{
		"message":  "Invalid Apikey",
		"status":   "success",
		"code":     http.StatusOK,
		"response": requestAddDevice,
	})
}
func adddeviceui(res http.ResponseWriter, req *http.Request) {
	//userID := req.FormValue("userEditId")

	err := tpl.ExecuteTemplate(res, "adddeviceui.gohtml", nil)
	if err != nil {
		log.Fatalln("template didn't execute: ", err)
	}

}
func savedevice(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	devicecode := request.FormValue("devicecode")

	type Dev struct {
		Name       string
		DeviceCode string
		ApiKey     string
	}
	a := Dev{name, devicecode, userApiKey}
	jsonReq, _ := json.Marshal(a)
	resp, err := http.Post(baseUrl+"adddevice", "application/json; charset=utf-8", bytes.NewBuffer(jsonReq))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	http.Redirect(response, request, "/devices", http.StatusFound)

}

func deleteuser(response http.ResponseWriter, request *http.Request) {
	id := request.FormValue("userDeleteId")
	_, err := db.Query("delete from `user` where id = ?", id)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		http.Redirect(response, request, "/users", http.StatusFound)

	}

}
