package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"git.rootprojects.org/root/keypairs"
)

var (
	name    = "keypairs"
	version = "0.0.0"
	date    = "0001-01-01T00:00:00Z"
	commit  = "0000000"
)

func usage() {
	ver()
	fmt.Println("Usage")
	fmt.Printf(" %s <command> [flags] args...\n", name)
	fmt.Println("")
	fmt.Printf("See usage: %s help <command>\n", name)
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("    version")
	fmt.Println("    gen")
	fmt.Println("    sign")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("    keypairs gen -o key.jwk.json [--pub <public-key>]")
	fmt.Println("    keypairs sign --exp 15m key.jwk.json payload.json")
	fmt.Println("    keypairs sign --exp 15m key.jwk.json '{ \"sub\": \"xxxx\" }'")
	fmt.Println("")
	//fmt.Println("  verify")
}

func ver() {
	fmt.Printf("%s v%s %s (%s)\n", name, version, commit[:7], date)
}

func main() {
	args := os.Args[:]

	if "help" == args[1] {
		// top-level help
		if 2 == len(args) {
			usage()
			os.Exit(0)
			return
		}
		// move help to subcommand argument
		self := args[0]
		args = append([]string{self}, args[2:]...)
		args = append(args, "--help")
	}

	switch args[1] {
	case "version":
		ver()
		os.Exit(0)
		return
	case "gen":
		gen(args)
	case "sign":
		sign(args)
	default:
		usage()
		os.Exit(1)
		return
	}
}

func gen(args []string) {
	var keyname string
	var pubname string
	flags := flag.NewFlagSet("gen", flag.ExitOnError)
	flags.StringVar(&keyname, "o", "", "private key file (ex: key.jwk.json or key.pem)")
	flags.StringVar(&pubname, "pub", "", "public key file (ex: pub.jwk.json or pub.pem)")
	flags.Parse(args)

	key := keypairs.NewDefaultPrivateKey()
	marshalPriv(key, keyname)
	pub := keypairs.NewPublicKey(key.Public())
	marshalPub(pub, pubname)
}

func sign(args []string) {
	var exp time.Duration
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	flags.DurationVar(&exp, "exp", 0, "duration until token expires (Default 15m)")
	flags.Parse(args)
	if len(flags.Args()) <= 3 {
		fmt.Fprintf(os.Stderr, "Usage: keypairs sign --exp 1h <private PEM or JWK> ./payload.json\n")
		os.Exit(1)
	}

	keyname := flags.Args()[2]
	payload := flags.Args()[3]

	var key keypairs.PrivateKey = nil
	b, err := ioutil.ReadFile(keyname)
	if nil != err {
		var err2 error
		key, err2 = keypairs.ParsePrivateKey([]byte(keyname))
		if nil != err2 {
			fmt.Fprintf(os.Stderr,
				"could not read private key as file (or parse as string) %q: %s\n", keyname, err)
		}
		os.Exit(1)
		return
	}
	if nil == key {
		var err3 error
		key, err3 = keypairs.ParsePrivateKey(b)
		if nil != err3 {
			fmt.Fprintf(os.Stderr,
				"could not parse private key from file %q: %s\n", keyname, err3)
			os.Exit(1)
			return
		}
	}

	if "" == payload {
		payload = "{}"
	}

	b, err = ioutil.ReadFile(payload)
	claims := map[string]interface{}{}
	if nil != err {
		var err2 error
		err2 = json.Unmarshal([]byte(payload), &claims)
		if nil != err2 {
			fmt.Fprintf(os.Stderr,
				"could not read payload as file (or parse as string) %q: %s\n", payload, err)
			os.Exit(1)
			return
		}
	}
	if 0 == len(claims) {
		var err3 error
		err3 = json.Unmarshal(b, &claims)
		if nil != err3 {
			fmt.Fprintf(os.Stderr,
				"could not parse palyoad from file %q: %s\n", payload, err3)
			os.Exit(1)
			return
		}
	}

	if 0 != exp {
		claims["exp"] = exp.Seconds()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = (15 * time.Minute).Seconds()
	}

	jws, err := keypairs.SignClaims(key, nil, claims)
	if nil != err {
		fmt.Fprintf(os.Stderr, "could not sign claims: %v\n%#v\n", err, claims)
		os.Exit(1)
		return
	}

	b, _ = json.Marshal(&jws)
	fmt.Printf("JWS:\n%s\n\n", indentJSON(b))
	fmt.Printf("JWT:\n%s\n\n", keypairs.JWSToJWT(jws))
}

func marshalPriv(key keypairs.PrivateKey, keyname string) {
	if "" == keyname {
		b := indentJSON(keypairs.MarshalJWKPrivateKey(key))

		fmt.Fprintf(os.Stdout, string(b)+"\n")
		return
	}

	var b []byte
	if strings.HasSuffix(keyname, ".json") {
		b = indentJSON(keypairs.MarshalJWKPrivateKey(key))
	} else if strings.HasSuffix(keyname, ".pem") {
		b, _ = keypairs.MarshalPEMPrivateKey(key)
	} else if strings.HasSuffix(keyname, ".der") {
		b, _ = keypairs.MarshalDERPrivateKey(key)
	} else {
		fmt.Fprintf(os.Stderr, "private key extension should be .jwk.json, .pem, or .der")
		os.Exit(1)
		return
	}

	ioutil.WriteFile(keyname, b, 0600)
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
	return append(b, '\n')
}
