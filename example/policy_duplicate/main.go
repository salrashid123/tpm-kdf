package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	_ "crypto/sha256"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmkdf "github.com/salrashid123/tpm-kdf"
	tpmkdfpolicy "github.com/salrashid123/tpm-kdf/policy"
	tpmutil "github.com/salrashid123/tpm-kdf/util"
)

var (
	tpmPath                   = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in                        = flag.String("in", "certs_ek/tpm-key.pem", "privateKey File")
	key                       = flag.String("key", "my_api_key", "API KEY")
	password                  = flag.String("password", "bar", "key password")
	tpmsessionencryptwithname = flag.String("tpm-session-encrypt-with-name", "", "Session encryption name")
)

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
	flag.Parse()

	keyLengthBits := uint32(256)

	////  using TPM
	c, err := os.ReadFile(*in)
	if err != nil {
		fmt.Printf("error %v\n", err)
		return 1
	}

	rwc, err := tpmutil.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Printf("can't open TPM %q: %v", *tpmPath, err)
		return 1
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Printf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	p, err := tpmkdfpolicy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*password), primaryKey.Name, primaryKey.ObjectHandle)
	if err != nil {
		log.Printf("ERROR:  could not get NewPolicyAuthValueAndDuplicateSelectSession: %v", err)
		return 1
	}

	label := []byte("foo")
	context := []byte("context")

	prf, err := tpmkdf.NewTPMPRF("", rwc, c, tpmkdfpolicy.RSA_EK, nil, p, *tpmsessionencryptwithname)
	if err != nil {
		fmt.Printf("error PRF %v\n", err)
		return 1
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
		fmt.Printf("error getting KDF %v\n", err)
		return 1
	}

	fmt.Printf("Derived Key (%d bytes): %x\n", len(derivedKey), derivedKey)
	return 0
}
