package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type Files struct {
	Id   int    `json:"Id"`
	Name string `json:"Name"`
	Size int    `json:"Size"`
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
func postFile(c *gin.Context) {
	err := c.Request.ParseMultipartForm(10 << 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	file, f_handler, err := c.Request.FormFile("uploadFile")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer file.Close()
	out_file, err := os.Create("./upload/" + f_handler.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer out_file.Close()
	_, err = io.Copy(out_file, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	addFileInDB(Files{db_last_id + 1, f_handler.Filename, int(f_handler.Size)})

	// Возвращаем успешный ответ
	c.JSON(http.StatusOK, gin.H{
		"message": "File " + f_handler.Filename + " uploaded successfully!",
	})
}

// список файлов
func getFile(c *gin.Context) {
	c.JSON(200, db_files)
}

func getMetaData(id int) string {
	for _, file := range db_files {
		if file.Id != id {
			continue
		}
		str := "Filename:" + file.Name + "\nSize:" + strconv.Itoa(file.Size) + "bytes"
		return str
	}
	return "Not found"
}

// Данные файла
func getIdFile(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ID must be number": err.Error()})
	}
	str := getMetaData(id)
	c.JSON(http.StatusOK, gin.H{
		"message": str,
	})
}

func middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		fmt.Fprintf(w, "Путь: %s\n", path)

		if path == "/files" {
			next(w, r)
		} else {
			http.NotFound(w, r)
		}
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

func getDBFiles() {
	filename, err := ioutil.ReadFile(db_json)
	if err != nil {
		fmt.Println(err)
		os.Create(db_json)
		return
	}
	json.Unmarshal(filename, &db_files)
}

func checkFilesInFolder() {
	files, err := os.ReadDir("./upload")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, file := range files {
		if file.Name() == "db.json" {
			continue
		}
		if !thisFileInDB(file.Name()) {
			err := os.Remove("./upload/" + file.Name())
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

func thisFileInDB(filename string) bool {
	for _, file := range db_files {
		if file.Name == filename {
			return true
		}
	}
	return false
}

func getLastID() {
	for i := 0; i < len(db_files); i++ {
		db_last_id = max(db_last_id, db_files[i].Id)
	}
}

func checkDeletedFiles() {
	files, err := os.ReadDir("./upload")
	if err != nil {
		fmt.Println(err)
		return
	}
	db_files_copy := make([]Files, 0)
	copy(db_files_copy, db_files)
	for i, file := range db_files_copy {
		if noFileInFolder(file, files) {
			db_files = slices.Delete(db_files, i, i+1) //потенциальный баг, проверить
		}
	}
}

func noFileInFolder(file_db Files, files []os.DirEntry) bool {
	for _, file := range files {
		if file_db.Name == file.Name() {
			return false
		}
	}
	return true
}

func main() {
	//обновляем базу данных файлов в папке
	getDBFiles()
	checkFilesInFolder()
	checkDeletedFiles()
	getLastID()

	// Регистрируем обработчик для пути "/"
	r := gin.Default()
	// Применяем middleware ко всем маршрутам
	r.Use(loggingMiddleware())
	r.GET("/", indexHandler)
	r.GET("/files", getFile)
	r.POST("/files", postFile)
	r.GET("/files/:id", getIdFile)

	r.Run(":8080")
}
