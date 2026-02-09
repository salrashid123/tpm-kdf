package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	tpmkdf "github.com/salrashid123/tpm-kdf"
)

var (
	tpmPath               = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	parentPass            = flag.String("parentPass", "", "Passphrase for the key  parent ")
	keyPass               = flag.String("keyPass", "", "Passphrase for the key ")
	label                 = flag.String("label", "foo", "source data label (this the label)")
	context               = flag.String("context", "", "source context derive data (this is the context)")
	length                = flag.Int("length", 256, "Lenth of derived key")
	keyFile               = flag.String("keyFile", "example/certs/tpm-key.pem", "PEM HMAC Key")
	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	outputBase64          = flag.Bool("outputBase64", false, "Output as base64")
)

func main() {

	flag.Parse()

	c, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-kdf: Error %v", err)
		os.Exit(1)
	}

	prf, err := tpmkdf.NewTPMPRF(*tpmPath, nil, c, []byte(*parentPass), []byte(*keyPass), *sessionEncryptionName)
	if err != nil {
		fmt.Printf("error %v\n", err)
		return
	}

	// Derive the key using the Counter Mode KDF
	derivedKey, err := tpmkdf.CounterModeKey(
		prf,              // The pseudorandom function (HMAC-SHA256)
		nil,              // The master secret key
		[]byte(*label),   // Optional label
		[]byte(*context), // Optional context
		uint32(*length),  // Desired key length in bits
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-kdf: Error %v", err)
		os.Exit(1)
	}

	if *outputBase64 {
		fmt.Printf("%s", base64.StdEncoding.EncodeToString(derivedKey))
	} else {
		fmt.Printf("%s", hex.EncodeToString(derivedKey))
	}
}
