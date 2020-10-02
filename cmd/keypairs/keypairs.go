package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"git.rootprojects.org/root/keypairs"
)

func main() {
	if 1 == len(os.Args) || "gen" != os.Args[1] {
		fmt.Fprintln(os.Stderr, "Usage: keypairs gen -o <filename> [--pub <filename>]")
		os.Exit(1)
		return
	}

	var privname string
	var pubname string
	flag.StringVar(&privname, "o", "", "private key file (should have .jwk.json or pkcs8.pem extension)")
	flag.StringVar(&pubname, "pub", "", "public key file (should have .jwk.json or spki.pem extension)")
	flag.Parse()

	priv := keypairs.NewDefaultPrivateKey()
	marshalPriv(priv, privname)
	marshalPub(keypairs.NewPublicKey(priv.Public()), pubname)
}

func marshalPriv(priv keypairs.PrivateKey, privname string) {
	if "" == privname {
		b := indentJSON(keypairs.MarshalJWKPrivateKey(priv))

		fmt.Fprintf(os.Stdout, string(b)+"\n")
		return
	}

	var b []byte
	if strings.HasSuffix(privname, ".json") {
		b = indentJSON(keypairs.MarshalJWKPrivateKey(priv))
	} else if strings.HasSuffix(privname, ".pem") {
		b, _ = keypairs.MarshalPEMPrivateKey(priv)
	} else if strings.HasSuffix(privname, ".der") {
		b, _ = keypairs.MarshalDERPrivateKey(priv)
	} else {
		fmt.Fprintf(os.Stderr, "private key extension should be .jwk.json, .pem, or .der")
		os.Exit(1)
		return
	}

	ioutil.WriteFile(privname, b, 0600)
}

func marshalPub(pub keypairs.PublicKey, pubname string) {
	var b []byte
	if "" == pubname {
		b = indentJSON(keypairs.MarshalJWKPublicKey(pub))

		fmt.Fprintf(os.Stderr, string(b)+"\n")
		return
	}

	if strings.HasSuffix(pubname, ".json") {
		b = indentJSON(keypairs.MarshalJWKPublicKey(pub))
	} else if strings.HasSuffix(pubname, ".pem") {
		b, _ = keypairs.MarshalPEMPublicKey(pub)
	} else if strings.HasSuffix(pubname, ".der") {
		b, _ = keypairs.MarshalDERPublicKey(pub)
	}

	ioutil.WriteFile(pubname, b, 0644)
}

func indentJSON(b []byte) []byte {
	m := map[string]interface{}{}
	_ = json.Unmarshal(b, &m)
	b, _ = json.MarshalIndent(&m, "", "  ")
	return b
}
