package keyserve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	keypairs "github.com/big-squid/go-keypairs"
)

func TestServeKeys(t *testing.T) {
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubs := []keypairs.PublicKey{
		keypairs.NewPublicKey(eckey.Public()),
	}

	addr := ":62017"
	done := make(chan bool, 1)

	h := &http.Server{Addr: addr, Handler: &server{Middleware: Middleware{Keys: pubs}}}

	logger := log.New(os.Stdout, "", 0)

	go func() {
		logger.Printf("Listening on http://0.0.0.0%s\n", addr)

		if err := h.ListenAndServe(); err != nil {
			// TODO check for the non-error server closed error
			//logger.Fatal(err)
		}

		done <- true
	}()

	go func() {
		time.Sleep(15 * time.Second)
		ctx, _ := context.WithTimeout(context.Background(), 15*time.Second)
		h.Shutdown(ctx)
	}()

	m := map[string]string{}
	resp, err := http.Get("http://localhost" + addr + "/.well-known/openid-configuration")
	if nil != err {
		log.Fatal(err)
	}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&m)
	if nil != err {
		log.Fatal(err)
	}

	n := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: []map[string]interface{}{},
	}
	resp, err = http.Get(m["jwks_uri"])
	if nil != err {
		log.Fatal(err)
	}
	dec = json.NewDecoder(resp.Body)
	err = dec.Decode(&n)
	if nil != err {
		log.Fatal(err)
	}

	resp, err = http.Get("http://localhost" + addr + "/pem")
	if nil != err {
		log.Fatal(err)
	}
	bytes, err := ioutil.ReadAll(resp.Body)
	if nil != err {
		log.Fatal(err)
	}
	_, err = keypairs.ParsePublicKey(bytes)
	if nil != err {
		log.Fatal("Could not parse PEM/cert from self")
		log.Fatal(err)
	}

	h.Shutdown(context.Background())
	<-done
}

type server struct {
	Middleware Middleware
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.Middleware.Handler(w, r) {
		w.Write([]byte("Try .well-known/openid-configuration or .well-known/jwks.json"))
	}
}
