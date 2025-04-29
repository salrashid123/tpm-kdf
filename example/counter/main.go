package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/hashicorp/vault/sdk/helper/kdf"
	tkdf "github.com/salrashid123/tpm-kdf/hmac"
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

	prf := kdf.HMACSHA256PRF
	prfLen := kdf.HMACSHA256PRFLen

	/// Usng Vault; we're doign this just to compare
	out, err := kdf.CounterMode(prf, prfLen, []byte(*key), b, 256)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Vault  KDF %s\n", hex.EncodeToString(out))

	////  using TPM

	rc, err := kdf.CounterMode(func(key []byte, data []byte) ([]byte, error) {
		return tkdf.TPMHMAC(*tpmPath, nil, c, nil, nil, false, data)
	}, prfLen, nil, b, 256)
	if err != nil {
		panic(err)
	}
	fmt.Printf("CounterModeKey   TPM  KDF %s\n", hex.EncodeToString(rc))

}
