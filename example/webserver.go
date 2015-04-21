package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/d4l3k/quic"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("alternate-protocol", "quic:8443")
	fmt.Fprintf(w, "Should redirect to QUIC.")
}

func main() {
	ql, err := quic.Listen(8443)
	if err != nil {
		panic(err)
	}
	defer ql.Close()

	log.Println("Running")

	http.HandleFunc("/", handler)
	http.ListenAndServe(":8443", nil)
	/*err = http.ListenAndServeTLS(":8443", "keys/cert.pem", "keys/key.pem", nil)
	if err != nil {
		panic(err)
	}*/
}
