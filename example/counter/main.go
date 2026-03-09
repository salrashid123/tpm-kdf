package main

import (
	"flag"
	"fmt"
	"os"

	_ "crypto/sha256"

	tpmkdf "github.com/salrashid123/tpm-kdf"
	tpmkdfpolicy "github.com/salrashid123/tpm-kdf/policy"
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "certs/tpm-key.pem", "privateKey File")
	key     = flag.String("key", "my_api_key", "API KEY")
)

func main() {

	flag.Parse()

	keyLengthBits := uint32(256)

	////  using TPM
	c, err := os.ReadFile(*in)
	if err != nil {
		fmt.Printf("error %v\n", err)
		return
	}

	label := []byte("foo")
	context := []byte("context")

	prf, err := tpmkdf.NewTPMPRF(*tpmPath, nil, c, tpmkdfpolicy.H2, nil, nil, "")
	if err != nil {
		fmt.Printf("error %v\n", err)
		return
	}
	// Derive the key using the Counter Mode KDF
	derivedKey, err := tpmkdf.CounterModeKey(
		prf,           // The pseudorandom function (HMAC-SHA256)
		nil,           // The master secret key
		label,         // Optional label
		context,       // Optional context
		keyLengthBits, // Desired key length in bits
	)
	if err != nil {
		fmt.Printf("error %v\n", err)
		return
	}

	fmt.Printf("Derived Key (%d bytes): %x\n", len(derivedKey), derivedKey)

}
