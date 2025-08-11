package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Секретный ключ для подписи JWT (в реальном приложении храни в переменной окружения)
const (
	dbConnStr = "host=localhost port=5432 user=postgres password=yourpassword dbname=file_upload sslmode=disable"
	jwtSecret = "filerestapi"
)

// LoginRequest Структура для логина
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims Структура для Claims (данные в Payload JWT)
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type User struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Username     string `gorm:"unique;not null" json:"username"`
	PasswordHash string `gorm:"not null" json:"password_hash"`
}

type Files struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `gorm:"not null" json:"name"`
	Size      int       `gorm:"not null" json:"size"`
	UserID    uint      `gorm:"not null" json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	db_files   []Files
	db_json    = "./upload/db.json"
	db_last_id int
)

func addFileInDB(file Files) {
	db_files = append(db_files, file)
}

func indexHandler(c *gin.Context) {
	// Отдаём HTML-форму
	tmpl := `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>File Upload</title>
    </head>
    <body>
        <h2>Upload a File</h2>
        <form action="/files" method="post" enctype="multipart/form-data">
            <label for="description">Description:</label>
            <input type="text" Name="description" Id="description"><br><br>
            <label for="uploadFile">Choose file:</label>
            <input type="file" Name="uploadFile" Id="uploadFile"><br><br>
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    `
	c.Header("Content-Type", "text/html")
	c.Writer.Write([]byte(tmpl))
}

// Обработчик HTTP-запросов
func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Привет, я последний хэндлер!"))
}

// Загрузка файла
func postFile(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := c.Request.ParseMultipartForm(10 << 20)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		file, fHandler, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer file.Close()
		outFile, err := os.Create("./upload/" + fHandler.Filename)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer outFile.Close()
		_, err = io.Copy(outFile, file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		userID := c.MustGet("user_id").(uint)
		fileData := Files{
			Name:   fHandler.Filename,
			Size:   int(fHandler.Size),
			UserID: userID,
		}
		if err := db.Create(&fileData).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения в БД"})
			return
		}

		// Возвращаем успешный ответ
		c.JSON(http.StatusOK, gin.H{
			"message": "File " + fHandler.Filename + " uploaded successfully!",
		})
	}
}

// Список файлов
func getFile(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var files []Files
		db.Where(&Files{UserID: c.MustGet("user_id").(uint)}).Find(&files)
		c.JSON(200, files)
	}
}

// Данные файла
func getIdFile(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"ID must be number": err.Error()})
		}
		var file Files
		db.Where("id = ?", id).First(&file)
		c.JSON(http.StatusOK, file)
	}
}

func postLogin(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var login LoginRequest
		if err := c.ShouldBindJSON(&login); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный JSON"})
			return
		}
		// Проверка логина и пароля
		var user User
		if err := db.Where("username = ?", login.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные1"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(login.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные2"})
			return
		}

		// Создаём JWT
		claims := &Claims{
			UserID:   user.ID,
			Username: user.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Срок действия 24 часа
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Subject:   login.Username,
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания токена"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

// Middleware для проверки JWT
func jwtMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Извлекаем токен из заголовка Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен отсутствует или неверный формат"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Парсим и проверяем токен
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("неверный метод подписи")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный или истёкший токен"})
			c.Abort()
			return
		}

		var user User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не найден"})
			c.Abort()
			return
		}

		// Сохраняем данные из токена в контексте
		c.Set("user_id", user.ID)
		c.Next()
	}
}

func loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next() // Вызываем следующий обработчик
		duration := time.Since(start)
		log.Printf("Запрос: %s %s, время выполнения: %v", c.Request.Method, c.Request.URL.Path, duration)
	}
}

func main() {
	//Работа с DB
	var db, err = gorm.Open(postgres.Open(dbConnStr), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	err = db.AutoMigrate(&User{}, &Files{})
	if err != nil {
		panic(err)
	}
	tables, err := db.Migrator().GetTables()
	if err != nil {
		fmt.Println("Ошибка при получении таблиц:", err)
	} else {
		fmt.Println("Таблицы в базе:", tables)
	}
	// Регистрируем обработчик для пути "/"
	r := gin.Default()

	r.GET("/", indexHandler)

	// Применяем middleware ко всем маршрутам
	r.Use(loggingMiddleware())

	// Эндпоинт для логина (генерация JWT)
	r.POST("/login", postLogin(db))

	protected := r.Group("/files")
	protected.Use(jwtMiddleware(db))

	protected.GET("/", getFile(db))
	protected.POST("/", postFile(db))
	protected.GET("/:id", getIdFile(db))

	r.Run(":8080")
}
