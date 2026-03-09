package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	_ "crypto/sha256"

	"github.com/google/go-tpm/tpm2/transport"
	tpmkdf "github.com/salrashid123/tpm-kdf"
	tpmkdfpolicy "github.com/salrashid123/tpm-kdf/policy"
	tpmutil "github.com/salrashid123/tpm-kdf/util"
)

var (
	tpmPath                   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in                        = flag.String("in", "certs_policy_password/tpm-key.pem", "privateKey File")
	key                       = flag.String("key", "my_api_key", "API KEY")
	password                  = flag.String("password", "testpswd", "key password")
	tpmsessionencryptwithname = flag.String("tpm-session-encrypt-with-name", "", "Session encryption name")
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

	rwc, err := tpmutil.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	p, err := tpmkdfpolicy.NewPasswordAuthSession(rwr, []byte(*password), 0)
	if err != nil {
		log.Printf("ERROR:  could not get MarshalPKIXPublicKey: %v", err)
		return
	}

	label := []byte("foo")
	context := []byte("context")

	prf, err := tpmkdf.NewTPMPRF("", rwc, c, nil, p, *tpmsessionencryptwithname)
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
