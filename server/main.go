package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type Foo struct {
	Foo string `json:"foo"`
}

type Data struct {
	A bool   `json:"a"`
	B string `json:"b"`
	C string `json:"c"`
	D string `json:"d"`
	E string `json:"e"`
	F string `json:"f"`
	G string `json:"g"`
	H string `json:"h"`
	I string `json:"i"`
	J string `json:"j"`
}

type Hash struct {
	Ah   string `json:"ah"`
	Av   string `json:"av"`
	Csrf string `json:"csrf"`
}

type Windows struct {
	Bar  []string `json:"bar"`
	Cask string   `json:"cask"`
}

func getRoot(c *gin.Context) {
	c.String(http.StatusOK, "Success")
}

func postAuthenticate(c *gin.Context) {
	var foo Foo
	if err := c.BindJSON(&foo); err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	// Decrypt foo
	decrypted, err := DecryptData(foo.Foo, key, iv)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	var data Data
	err = json.Unmarshal([]byte(decrypted), &data)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	csrf, err := EncryptData(data.I, key_csrf, iv_csrf)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	// Generate the auth response
	hash := Hash{
		Ah:   computeHash(data.H, data.E, AV[c.Param("name")]),
		Av:   AV[c.Param("name")],
		Csrf: csrf,
	}

	jsonData, err := json.Marshal(hash)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	// Encrypt the string
	encrypted, err := EncryptData(string(jsonData), key, iv)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	c.JSON(
		http.StatusOK,
		Foo{Foo: encrypted},
	)
}

func postRun(c *gin.Context) {
	var foo Foo
	if err := c.BindJSON(&foo); err != nil {
		return
	}

	decrypted, err := DecryptData(foo.Foo, key, iv)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	var windows Windows
	err = json.Unmarshal([]byte(decrypted), &windows)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	// Find the index of the puzzle pirates window in the list of windows
	index := -1
	for i, s := range windows.Bar {
		if strings.Contains(s, "Puzzle Pirates -") && strings.Contains(s, "on the ") && strings.Contains(s, "ocean") {
			index = i
			break
		}
	}

	// Encrypt the string
	encrypted, err := EncryptData(strconv.Itoa(index), key, iv)
	if err != nil {
		c.String(http.StatusBadRequest, "Error")
		return
	}

	c.JSON(
		http.StatusOK,
		Foo{Foo: encrypted},
	)
}

func main() {
	certfile := flag.String("certfile", "cert.pem", "Path to the certificate file")
	keyfile := flag.String("keyfile", "key.pem", "Path to the key file")
	flag.Parse()

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.SetTrustedProxies(nil)

	router.GET("/", getRoot)
	router.POST("/Authenticator/Authenticate/:name", postAuthenticate)
	router.POST("/Authenticator/Run/:name/Run", postRun)

	router.RunTLS("127.0.0.1:443", *certfile, *keyfile)
	// router.Run("127.0.0.1:7777")
}
