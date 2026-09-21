// The local example upstream makes successful forwarding distinguishable from a proxy denial.
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// main serves the fixture response used by the local gateway example.
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("origin path=%s request_id=%s", r.URL.Path, r.Header.Get("X-Request-Id"))
		fmt.Fprintf(w, "upstream reached: %s\n", r.URL.Path)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
