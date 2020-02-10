package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var videos map[string]string

func init() {
	videos = make(map[string]string)
}

func setupRoutes() {
	http.HandleFunc("/upload", uploadFile)
	http.HandleFunc("/download", downloadFile)
	http.ListenAndServe(":8080", nil)
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("File Upload Endpoint Hit")

	// Parse our multipart form, 10 << 20 specifies a maximum
	// upload of 10 MB files.
	r.ParseMultipartForm(10 << 20)
	// FormFile returns the first file for the given key `myFile`
	// it also returns the FileHeader so we can get the Filename,
	// the Header and the size of the file
	form := r.Form
	name := form.Get("name")
	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println("Error Retrieving the File")
		fmt.Println(err)
		return
	}
	defer file.Close()
	fmt.Printf("Uploaded File: %+v\n", handler.Filename)
	fmt.Printf("File Size: %+v\n", handler.Size)
	fmt.Printf("MIME Header: %+v\n", handler.Header)

	// Create a temporary file within our temp-images directory that follows
	// a particular naming pattern
	f, _ := os.Create("./data/" + name)
	defer f.Close()

	//tempFile, err := ioutil.TempFile("data", "upload.mp4")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//defer tempFile.Close()

	// read all of the contents of our uploaded file into a
	// byte array
	tempBytes, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}

	encryptedBytes := encryptFile(handler.Filename, tempBytes, "1234")


	// write this byte array to our temporary file
	f.Write(encryptedBytes)
	videos[name] = "./data/" + name
	// return that we have successfully uploaded our file!
	fmt.Fprintf(w, "Successfully Uploaded File\n")
}

func downloadFile(w http.ResponseWriter, r *http.Request){
	start := time.Now()
	defer func(start time.Time) {
		fmt.Println("processTime: ", time.Since(start).Seconds(), " s")
	}(start)


	type Data struct {
		Name string `json:"name"`
		Key string `json:"key"`
	}

	var param Data

	bindJSON(r, &param)

	if param.Key != "" {
		data, ok := videos[param.Name]
		if ok {
			fmt.Println("data ", data)
		}
		// data := "./data/upload.mp4194583897"

		bytes, err := decryptFile(data, param.Key)
		if err != nil {
			w.Write([]byte(err.Error()))
		} else {
			w.Write(bytes)
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

// createHash
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func encryptFile(filename string, data []byte, passphrase string) []byte {
	return encrypt(data, passphrase)
}

func decryptFile(filename string, passphrase string) ([]byte, error) {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func main() {
	setupRoutes()
	fmt.Println("server started")
}

func bindJSON(req *http.Request, obj interface{}) error {
	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(obj); err != nil {
		return err
	}

	return nil
}