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
	fmt.Println(ver())
	fmt.Println()
	fmt.Println("Usage")
	fmt.Printf(" %s <command> [flags] args...\n", name)
	fmt.Println("")
	fmt.Printf("See usage: %s help <command>\n", name)
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("    version")
	fmt.Println("    gen")
	fmt.Println("    sign")
	fmt.Println("    verify")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("    keypairs gen --key key.jwk.json [--pub <public-key>]")
	fmt.Println("")
	fmt.Println("    keypairs sign --exp 15m key.jwk.json payload.json")
	fmt.Println("    keypairs sign --exp 15m key.jwk.json '{ \"sub\": \"xxxx\" }'")
	fmt.Println("")
	fmt.Println("    keypairs verify ./pub.jwk.json 'xxxx.yyyy.zzzz'")
	// TODO fmt.Println("    keypairs verify --issuer https://example.com '{ \"sub\": \"xxxx\" }'")
	fmt.Println("")
}

func ver() string {
	return fmt.Sprintf("%s v%s (%s) %s", name, version, commit[:7], date)
}

func main() {
	args := os.Args[:]

	if len(args) < 2 || "help" == args[1] {
		// top-level help
		if len(args) <= 2 {
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
		fmt.Println(ver())
		os.Exit(0)
		return
	case "gen":
		gen(args[2:])
	case "sign":
		sign(args[2:])
	case "verify":
		verify(args[2:])
	default:
		usage()
		os.Exit(1)
		return
	}
}

func gen(args []string) {
	var keyname string
	var keynameAlt string
	//var keynameAlt2 string
	var pubname string
	flags := flag.NewFlagSet("gen", flag.ExitOnError)
	flags.StringVar(&keynameAlt, "o", "", "output file (alias of --key)")
	//flags.StringVar(&keynameAlt2, "priv", "", "private key file (alias of --key)")
	flags.StringVar(&keyname, "key", "", "private key file (ex: key.jwk.json or key.pem)")
	flags.StringVar(&pubname, "pub", "", "public key file (ex: pub.jwk.json or pub.pem)")
	flags.Parse(args)

	if 0 == len(keyname) {
		keyname = keynameAlt
	}
	/*
		if 0 == len(keyname) {
			keyname = keynameAlt2
		}
	*/

	key := keypairs.NewDefaultPrivateKey()
	marshalPriv(key, keyname)
	pub := key.Public().(keypairs.PublicKey)
	marshalPub(pub, pubname)
}

func sign(args []string) {
	var exp time.Duration
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	flags.DurationVar(&exp, "exp", 0, "duration until token expires (Default 15m)")
	flags.Parse(args)
	if len(flags.Args()) <= 1 {
		fmt.Fprintf(os.Stderr, "Usage: keypairs sign --exp 1h <private PEM or JWK> ./payload.json\n")
		os.Exit(1)
	}

	keyname := flags.Args()[0]
	payload := flags.Args()[1]

	key, err := readKey(keyname)
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	if "" == payload {
		// TODO should this be null? I forget
		payload = "{}"
	}

	b, err := ioutil.ReadFile(payload)
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
	fmt.Fprintf(os.Stderr, "%s\n", indentJSON(b))
	fmt.Fprintf(os.Stdout, "%s\n", keypairs.JWSToJWT(jws))
}

func verify(args []string) {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Println("Usage: keypairs verify <public key> <jwt-or-jwt>")
		fmt.Println("")
		fmt.Println("    <public key>: a File or String of an EC or RSA key in JWK or PEM format")
		fmt.Println("    <jwt-or-jws>: a JWT or JWS File or String, if JWS the payload must be Base64")
		fmt.Println("")
	}
	flags.Parse(args)
	if len(flags.Args()) <= 1 {
		flags.Usage()
		os.Exit(1)
	}

	pubname := flags.Args()[0]
	payload := flags.Args()[1]

	pub, err := readPub(pubname)
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	jws, err := readJWS(payload)
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
		return
	}

	b, _ := json.Marshal(&jws)
	fmt.Fprintf(os.Stdout, "%s\n", indentJSON(b))

	errs := keypairs.VerifyClaims(pub, jws)
	if nil != errs {
		fmt.Fprintf(os.Stderr, "error:\n")
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "\t%v\n", err)
		}
		os.Exit(1)
		return
	}
	fmt.Fprintf(os.Stderr, "Signature is Valid\n")
}

func readKey(keyname string) (keypairs.PrivateKey, error) {
	var key keypairs.PrivateKey = nil

	// Read as file
	b, err := ioutil.ReadFile(keyname)
	if nil != err {
		// Tis not a file! Perhaps a string?
		var err2 error
		key, err2 = keypairs.ParsePrivateKey([]byte(keyname))
		if nil != err2 {
			// Neither a valid string. Blast!
			return nil, fmt.Errorf(
				"could not read private key as file (or parse as string) %q:\n%s",
				keyname, err2,
			)
		}
	}

	if nil == key {
		var err3 error
		key, err3 = keypairs.ParsePrivateKey(b)
		if nil != err3 {
			return nil, fmt.Errorf(
				"could not parse private key from file %q:\n%s",
				keyname, err3,
			)
		}
	}

	return key, nil
}

func readPub(pubname string) (keypairs.PublicKey, error) {
	var pub keypairs.PublicKey = nil

	// Read as file
	b, err := ioutil.ReadFile(pubname)
	if nil != err {
		// No file? Try as string!
		pub2, err2 := keypairs.ParsePublicKey([]byte(pubname))
		if nil != err2 {
			return nil, fmt.Errorf(
				"could not read public key as file (or parse as string) %q:\n%w",
				pubname, err,
			)
		}
		pub = pub2.Key()
	}

	// Oh, it was a file.
	if nil == pub {
		pub3, err3 := keypairs.ParsePublicKey(b)
		if nil != err3 {
			return nil, fmt.Errorf(
				"could not parse public key from file %q:\n%w",
				pubname, err3,
			)
		}
		pub = pub3.Key()
	}

	return pub, nil
}

func readJWS(payload string) (*keypairs.JWS, error) {
	// Is it a file?
	b, err := ioutil.ReadFile(payload)
	if nil != err {
		// Or a JWS or JWS String!?
		b = []byte(payload)
	}

	// Either way, we have some bytes now
	jws := &keypairs.JWS{}
	jwt := string(b)
	jwsb := []byte(jwt)
	if !strings.Contains(jwt, " \t\n{}[]") {
		jws = keypairs.JWTToJWS(string(b))
		if nil != jws {
			b, _ = json.Marshal(jws)
			jwsb = (b)
		}
	}

	// And now we have a string that may be a JWS
	if err := json.Unmarshal(jwsb, &jws); nil != err {
		// Nope, it's not
		return nil, fmt.Errorf(
			"could not read signed payload from file or string as JWT or JWS %q:\n%w",
			payload, err,
		)
	}

	if err := jws.DecodeComponents(); nil != err {
		// bah! so close!
		return nil, fmt.Errorf(
			"could not decode the JWS Header and Claims components: %w\n%s",
			err, string(jwsb),
		)
	}

	return jws, nil
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
