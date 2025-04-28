package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/canonical/go-kbkdf"
	tpmkdf "github.com/salrashid123/tpm-kdf"
)

var (
	tpmPath      = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	parentPass   = flag.String("parentPass", "", "Passphrase for the key  parent ")
	keyPass      = flag.String("keyPass", "", "Passphrase for the key  key ")
	data         = flag.String("data", "foo", "source passphrase to derive data")
	length       = flag.Int("length", 256, "Lenth of derived key")
	keyFile      = flag.String("keyFile", "example/certs/tpm-key.pem", "PEM HMAC Key")
	outputBase64 = flag.Bool("outputBase64", false, "Output as base64")
)

func main() {

	flag.Parse()

	c, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-kdf: Error %v", err)
		os.Exit(1)
	}

	h, err := tpmkdf.TPMKDF(*tpmPath, nil, c, []byte(*parentPass), []byte(*keyPass))
	if err != nil {
		panic(err)
	}
	r := kbkdf.CounterModeKey(h, nil, nil, []byte(*data), uint32(*length))

	if *outputBase64 {
		fmt.Printf("%s", base64.StdEncoding.EncodeToString(r))
	} else {
		fmt.Printf("%s", hex.EncodeToString(r))
	}
}
