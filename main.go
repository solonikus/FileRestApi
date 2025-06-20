package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"slices"
)

type Files struct {
	id   int    `json:"id"`
	name string `json:"name"`
	size int    `json:"size"`
}

var (
	db_files   []Files
	db_json    = "./upload/db.json"
	db_last_id int
)

func addFileInDB(file Files) {
	db_files = append(db_files, file)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
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
            <input type="text" name="description" id="description"><br><br>
            <label for="uploadFile">Choose file:</label>
            <input type="file" name="uploadFile" id="uploadFile"><br><br>
            <input type="submit" value="Upload">
        </form>
    </body>
    </html>
    `
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, tmpl)
}

// Обработчик HTTP-запросов
func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Привет, я последний хэндлер!"))
}

func postFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	file, f_handler, err := r.FormFile("uploadFile")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()
	out_file, err := os.Create("./upload/" + f_handler.Filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer out_file.Close()
	_, err = io.Copy(out_file, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	addFileInDB(Files{db_last_id + 1, f_handler.Filename, int(f_handler.Size)})
	fmt.Fprintf(w, "File %s uploaded successfully!", f_handler.Filename)
}

func getFile(w http.ResponseWriter, r *http.Request) {

}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		getFile(w, r)
	} else if r.Method == "POST" {
		postFile(w, r)
	} else {
		http.Error(w, "Wrong method", http.StatusMethodNotAllowed)
	}
}

func middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		fmt.Fprintf(w, "Путь: %s\n", path)

		if path != "/files" {
			http.Error(w, "404 not found", http.StatusNotFound)
		}

		next(w, r)
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
		if file.Name() == db_json {
			continue
		}
		if !thisFileInDB(file.Name()) {
			os.Remove(file.Name())
		}
	}
}

func thisFileInDB(filename string) bool {
	for _, file := range db_files {
		if file.name == filename {
			return true
		}
	}
	return false
}

func getLastID() {
	for i := 0; i < len(db_files); i++ {
		db_last_id = max(db_last_id, db_files[i].id)
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
			db_files = slices.Delete(db_files, i, i+1)
		}
	}
}

func noFileInFolder(file_db Files, files []os.DirEntry) bool {
	for _, file := range files {
		if file_db.name == file.Name() {
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
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/files", middleware(uploadHandler))

	// Запускаем веб-сервер на порту 8080
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Ошибка запуска сервера:", err)
	}
}
