package main

import (
	"crypto/md5" // CVE-2004-2761
	"crypto/tls" // CVE-2017-10185
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dgrijalva/jwt-go"   // CVE-2020-26160
	"github.com/gin-gonic/gin"      // CVE-2022-21612
	"github.com/shopspring/decimal" // CVE-2020-35169

	"github.com/urfave/negroni" // CVE-2020-15112
	"gopkg.in/yaml.v2"          // CVE-2019-11254
)

func main() {
	// JWT Example with vulnerable package
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		fmt.Println("Error signing token:", err)
	}
	fmt.Println("Token:", tokenString)

	// Weak MD5 hashing example
	input := "some sensitive data"
	hash := md5.Sum([]byte(input))
	fmt.Printf("MD5 Hash: %x\n", hash)

	// Example with vulnerable decimal package
	d1 := decimal.NewFromFloat(1.2345)
	d2 := decimal.NewFromFloat(2.3456)
	sum := d1.Add(d2)
	fmt.Println("Decimal sum:", sum)

	// Insecure TLS configuration
	http.HandleFunc("/tls", func(w http.ResponseWriter, r *http.Request) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Vulnerable: should validate certificates
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

		resp, err := client.Get("https://example.com")
		if err != nil {
			http.Error(w, "Failed to fetch URL", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read response body", http.StatusInternalServerError)
			return
		}

		w.Write(body)
	})

	// Insecure file handling
	http.HandleFunc("/servefile", func(w http.ResponseWriter, r *http.Request) {
		filename := r.URL.Query().Get("file")
		// Vulnerable: no path sanitization
		filePath := filepath.Join("/var/www/files", filename)

		file, err := os.Open(filePath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		data, err := ioutil.ReadAll(file)
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusInternalServerError)
			return
		}

		w.Write(data)
	})

	// YAML parsing with a known vulnerable version
	http.HandleFunc("/yaml", func(w http.ResponseWriter, r *http.Request) {
		data := `
        key: !!binary |
          Y2hpY2tlbiwgZXNzZW4gZGllIHRyZSBsZWJlbg==
        `
		var m map[string]interface{}
		err := yaml.Unmarshal([]byte(data), &m)
		if err != nil {
			http.Error(w, "Failed to parse YAML", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Parsed YAML: %v", m)
	})

	// Example using negroni package with a known vulnerability
	n := negroni.New()
	n.Use(negroni.NewRecovery())

	router := gin.Default()
	router.GET("/negroni", func(c *gin.Context) {
		c.String(http.StatusOK, "This route is handled by negroni!")
	})

	// Integrating negroni with gin router
	n.UseHandler(router)

	// Starting the HTTP server
	n.Run(":8080")
}
