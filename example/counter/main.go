package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	kbkdf "github.com/canonical/go-kbkdf"
	"github.com/canonical/go-kbkdf/hmac_prf"

	tpmkdf "github.com/salrashid123/tpm-kdf"
)

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "certs/tpm-key.pem", "privateKey File")
	key     = flag.String("key", "my_api_key", "API KEY")
)

func main() {

	flag.Parse()
	b := []byte("foo")

	////  using TPM

	c, err := os.ReadFile(*in)
	if err != nil {
		panic(err)
	}

	k := []byte("my_api_key")
	r := kbkdf.CounterModeKey(hmac_prf.SHA256, k, nil, b, 256)
	fmt.Printf("CounterModeKey  kbkdf  KDF %s\n", hex.EncodeToString(r))

	h, err := tpmkdf.TPMKDF(*tpmPath, nil, c, nil, nil)
	if err != nil {
		panic(err)
	}
	rc := kbkdf.CounterModeKey(h, nil, nil, b, 256)
	fmt.Printf("CounterModeKey   TPM  KDF %s\n", hex.EncodeToString(rc))

}
