package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var validate *validator.Validate

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	Role     string `json:"role"`
	Teamid   uint   `json:"teamid"`
}

type Team struct {
	ID   uint   `json:"id"`
	Name string `json:"name" validate:"required"`
}

var jwtSecret = []byte("your-secret-key")

func initDB() {
	var err error

	dsn := "host=localhost port=5432 user=youruser password=yourpassword dbname=yourdbname sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect to database:", err)
	}

	err = db.AutoMigrate(&User{}, &Team{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}
	fmt.Println("Connected to database")
}

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing token")
		}
		parts := strings.Split(authHeader, "Bearer ")
		if len(parts) != 2 {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token format")
		}
		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid token")
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			user := &User{
				ID:       uint(claims["id"].(float64)),
				Username: claims["username"].(string),
				Role:     claims["role"].(string),
			}
			c.Set("user", user) // Store user info in context
		}

		return next(c)
	}
}

func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user")
		if user == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid user")
		}
		userObj := user.(*User)
		if userObj.Role != "admin" {
			return echo.NewHTTPError(http.StatusForbidden, "access denied")
		}
		return next(c)
	}
}

func signup(c echo.Context) error {
	user := new(User)
	if err := c.Bind(user); err != nil {
		return err
	}
	if err := validate.Struct(user); err != nil {
		return err
	}

	if err := db.Create(user).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create user")
	}
	return c.JSON(http.StatusOK, user)
}

func login(c echo.Context) error {
	user := new(User)
	if err := c.Bind(user); err != nil {
		return err
	}

	var dbUser User
	if err := db.Where("username = ?", user.Username).First(&dbUser).Error; err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}
	if dbUser.Password != user.Password {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       dbUser.ID,
		"username": dbUser.Username,
		"role":     dbUser.Role,
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, echo.Map{
		"token": tokenString,
	})
}

func createTeam(c echo.Context) error {
	team := new(Team)
	if err := c.Bind(team); err != nil {
		return err
	}
	if err := validate.Struct(team); err != nil {
		return err
	}

	if err := db.Create(team).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create team")
	}

	return c.JSON(http.StatusOK, team)
}

func addUserToTeam(c echo.Context) error {
	teamID := c.Param("team_id")
	userID := c.Param("user_id")

	var team Team
	var user User
	if err := db.First(&team, teamID).Error; err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "team not found")
	}
	if err := db.First(&user, userID).Error; err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	user.Teamid = team.ID
	if err := db.Save(&user).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to add user to team")
	}

	return c.JSON(http.StatusOK, user)
}

func removeUserFromTeam(c echo.Context) error {
	teamID := c.Param("team_id")
	userID := c.Param("user_id")

	var team Team
	var user User
	if err := db.First(&team, teamID).Error; err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "team not found")
	}
	if err := db.First(&user, userID).Error; err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}

	user.Teamid = 0
	if err := db.Save(&user).Error; err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to remove user from team")
	}

	return c.JSON(http.StatusOK, user)
}

func main() {

	initDB()
	validate = validator.New()

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.POST("/signup", signup)
	e.POST("/login", login)

	e.POST("/team", AuthMiddleware(AdminMiddleware(createTeam)))
	e.POST("/team/:team_id/user/:user_id", AuthMiddleware(AdminMiddleware(addUserToTeam)))
	e.DELETE("/team/:team_id/user/:user_id", AuthMiddleware(AdminMiddleware(removeUserFromTeam)))
	e.GET("/team/:team_id", func(c echo.Context) error {
		teamID := c.Param("team_id")
		var team Team
		if err := db.First(&team, teamID).Error; err != nil {
			return echo.NewHTTPError(http.StatusNotFound, "team not found")
		}

		// Find all users with the given Teamid
		var users []User
		if err := db.Where("teamid = ?", teamID).Find(&users).Error; err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to fetch users")
		}

		return c.JSON(http.StatusOK, users)
	})
	e.PATCH("/team/:team_id", AuthMiddleware(AdminMiddleware(func(c echo.Context) error {
		teamID := c.Param("team_id")

		var team Team
		if err := db.First(&team, teamID).Error; err != nil {
			return echo.NewHTTPError(http.StatusNotFound, "team not found")
		}

		type TeamUpdate struct {
			Name string `json:"name" validate:"required"`
		}

		teamUpdate := new(TeamUpdate)
		if err := c.Bind(teamUpdate); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid data")
		}

		team.Name = teamUpdate.Name

		if err := db.Save(&team).Error; err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to update team")
		}

		return c.JSON(http.StatusOK, team)
	})))

	e.Logger.Fatal(e.Start(":8080"))
}
