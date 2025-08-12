package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Секретный ключ для подписи JWT (в реальном приложении храни в переменной окружения)
const (
	dbConnStr = "host=localhost port=5432 user=postgres password=yourpassword dbname=file_upload sslmode=disable"
	jwtSecret = "filerestapi"
)

// App содержит все зависимости приложения
type App struct {
	DB     *gorm.DB
	Logger *zap.Logger
}

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
func (app *App) postFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uint)
		err := c.Request.ParseMultipartForm(10 << 20)
		if err != nil {
			app.Logger.Error("Failed to parse multipart form", zap.Error(err), zap.Uint("user_id", userID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		file, fHandler, err := c.Request.FormFile("file")
		if err != nil {
			app.Logger.Error("Failed to get file", zap.Error(err), zap.Uint("user_id", userID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer file.Close()
		outFile, err := os.Create("./upload/" + fHandler.Filename)
		if err != nil {
			app.Logger.Error("Failed to create file", zap.Error(err), zap.String("filename", fHandler.Filename), zap.Uint("user_id", userID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer outFile.Close()
		_, err = io.Copy(outFile, file)
		if err != nil {
			app.Logger.Error("Failed to save file", zap.Error(err), zap.String("filename", fHandler.Filename), zap.Uint("user_id", userID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		fileData := Files{
			Name:   fHandler.Filename,
			Size:   int(fHandler.Size),
			UserID: userID,
		}
		if err := app.DB.Create(&fileData).Error; err != nil {
			app.Logger.Error("Failed to save file metadata to DB", zap.Error(err), zap.String("filename", fHandler.Filename), zap.Uint("user_id", userID))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения в БД"})
			return
		}
		app.Logger.Info("File uploaded", zap.String("filename", fHandler.Filename), zap.Int("size", fileData.Size), zap.Uint("user_id", userID))
		// Возвращаем успешный ответ
		c.JSON(http.StatusOK, gin.H{
			"message": "File " + fHandler.Filename + " uploaded successfully!",
		})
	}
}

// Список файлов
func (app *App) getFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		var files []Files
		app.DB.Where(&Files{UserID: c.MustGet("user_id").(uint)}).Find(&files)
		app.Logger.Info("File list gets user", zap.Uint("user_id", c.MustGet("user_id").(uint)), zap.String("ip", c.ClientIP()))
		c.JSON(200, files)
	}
}

// Данные файла
func (app *App) getIdFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param("id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			app.Logger.Error("Failed to parse id", zap.Error(err), zap.String("id", idStr))
			c.JSON(http.StatusInternalServerError, gin.H{"ID must be number": err.Error()})
		}
		var file Files
		app.DB.Where("id = ?", id).First(&file)
		app.Logger.Info("File gets user", zap.String("id", idStr), zap.String("ip", c.ClientIP()))
		c.JSON(http.StatusOK, file)
	}
}

func (app *App) postLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		var login LoginRequest
		if err := c.ShouldBindJSON(&login); err != nil {
			app.Logger.Error("Failed to parse JSON", zap.Error(err), zap.String("ip", c.ClientIP()))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный JSON"})
			return
		}
		// Проверка логина и пароля
		var user User
		if err := app.DB.Where("username = ?", login.Username).First(&user).Error; err != nil {
			app.Logger.Warn("Invalid login attempt", zap.String("username", login.Username), zap.String("ip", c.ClientIP()))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные1"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(login.Password)); err != nil {
			app.Logger.Warn("Invalid password", zap.String("username", login.Username), zap.String("ip", c.ClientIP()))
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
			app.Logger.Error("Failed to create JWT", zap.Error(err), zap.String("username", user.Username))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка создания токена"})
			return
		}
		app.Logger.Info("User logged in", zap.String("username", user.Username), zap.Uint("user_id", user.ID), zap.String("ip", c.ClientIP()))
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	}
}

// Middleware для проверки JWT
func (app *App) jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Извлекаем токен из заголовка Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			app.Logger.Warn("Missing or invalid Authorization header", zap.String("ip", c.ClientIP()))
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
			app.Logger.Warn("Invalid JWT", zap.Error(err), zap.String("ip", c.ClientIP()))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный или истёкший токен"})
			c.Abort()
			return
		}

		var user User
		if err := app.DB.First(&user, claims.UserID).Error; err != nil {
			app.Logger.Warn("User not found", zap.Uint("user_id", claims.UserID), zap.String("ip", c.ClientIP()))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не найден"})
			c.Abort()
			return
		}

		app.Logger.Debug("JWT verified", zap.Uint("user_id", user.ID), zap.String("username", user.Username))
		// Сохраняем данные из токена в контексте
		c.Set("user_id", user.ID)
		c.Next()
	}
}

func (app *App) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next() // Вызываем следующий обработчик
		duration := time.Since(start)
		app.Logger.Info("Request took", zap.Duration("duration", duration), zap.String("ip", c.ClientIP()))
	}
}

// Инициализация логгера Zap
func setupLogger() *zap.Logger {
	logger, err := zap.NewProduction() // JSON-логи для продакшена
	if err != nil {
		panic(err)
	}
	return logger
}

func main() {
	// Инициализация логгера
	logger := setupLogger()
	defer logger.Sync()

	//Работа с DB
	var db, err = gorm.Open(postgres.Open(dbConnStr), &gorm.Config{})
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	err = db.AutoMigrate(&User{}, &Files{})
	if err != nil {
		logger.Fatal("Failed AutoMigrate", zap.Error(err))
	}
	//Проверка таблиц в базе
	tables, err := db.Migrator().GetTables()
	if err != nil {
		logger.Fatal("Failed GetTables", zap.Error(err))
	} else {
		logger.Info("Таблиц в базе данных:", zap.Strings("Таблиц в базе данных:", tables))
	}

	// Инициализация структуры App
	app := &App{
		DB:     db,
		Logger: logger,
	}

	// Регистрируем обработчик для пути "/"
	r := gin.Default()

	r.GET("/", indexHandler)

	// Применяем middleware ко всем маршрутам
	r.Use(app.loggingMiddleware())

	// Эндпоинт для логина (генерация JWT)
	r.POST("/login", app.postLogin())

	protected := r.Group("/files")
	protected.Use(app.jwtMiddleware())

	protected.GET("/", app.getFile())
	protected.POST("/", app.postFile())
	protected.GET("/:id", app.getIdFile())

	r.Run(":8080")
}

//TODO ендпоинты: adduser, deleteuser, deletefile, updateuser
