package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	tpmkdf "github.com/salrashid123/tpm-kdf"
	tpmkdfpolicy "github.com/salrashid123/tpm-kdf/policy"
)

var (
	tpmPath               = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	parentPass            = flag.String("parentPass", "", "Passphrase for the key  parent ")
	keyPass               = flag.String("keyPass", "", "Passphrase for the key ")
	pcrValues             = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	label                 = flag.String("label", "foo", "source data label (this the label)")
	context               = flag.String("context", "context", "source context derive data (this is the context)")
	parentKeyType         = flag.String("parentKeyType", "h2", "Type of the parent key (rsa_ek, ecc_ek, h2)")
	length                = flag.Int("length", 256, "Lenth of derived key")
	keyFile               = flag.String("keyFile", "example/certs/tpm-key.pem", "PEM HMAC Key")
	sessionEncryptionName = flag.String("tpm-session-encrypt-with-name", "", "hex encoded TPM object 'name' to use with an encrypted session")
	outputBase64          = flag.Bool("outputBase64", false, "Output as base64")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {

	flag.Parse()

	c, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-kdf: Error %v", err)
		return 1
	}

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-kdf: can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "tpm-kdf: can't close TPM %q: %v", *tpmPath, err)
			return
		}
	}()

	rwr := transport.FromReadWriter(rwc)
	var p tpmkdfpolicy.Session

	if *parentKeyType == "h2" {
		if *keyPass != "" {
			//rwr := transport.FromReadWriter(rwc)
			p, err = tpmkdfpolicy.NewPasswordAuthSession(rwr, []byte(*keyPass), 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "tpm-kdf:   could not get NewPasswordAuthSession: %v", err)
				return 1
			}
		} else if *pcrValues != "" {

			// get the specified pcrs

			_, pcrList, _, err := tpmkdfpolicy.GetPCRMap(tpm2.TPMAlgSHA256, *pcrValues)

			if err != nil {
				fmt.Fprintf(os.Stderr, "tpm-kdf:  Could not get PCRMap: %s", err)
				return 1
			}

			p, err = tpmkdfpolicy.NewPCRSession(rwr, []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrList...),
				},
			}, tpm2.TPM2BDigest{}, 0)

			if err != nil {
				fmt.Fprintf(os.Stderr, "tpm-kdf:  Could not get PCRMap: %s", err)
				return 1
			}
		}
	} else if *parentKeyType == "rsa_ek" {
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

		p, err = tpmkdfpolicy.NewPolicyAuthValueAndDuplicateSelectSession(rwr, []byte(*keyPass), primaryKey.Name, primaryKey.ObjectHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tpm-kdf:  Could not get PCRMap: %s", err)
			return 1
		}
	} else {
		fmt.Fprintf(os.Stderr, "tpm-kdf:  unsupported parentkey: %s", *parentKeyType)
		return 1
	}
	var prf tpmkdf.PRF
	if *parentKeyType == "rsa_ek" {
		prf, err = tpmkdf.NewTPMPRF("", rwc, c, tpmkdfpolicy.RSA_EK, []byte(*parentPass), p, *sessionEncryptionName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tpm-kdf:  %v\n", err)
			return 1
		}
	} else {
		prf, err = tpmkdf.NewTPMPRF("", rwc, c, tpmkdfpolicy.H2, []byte(*parentPass), p, *sessionEncryptionName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tpm-kdf:  %v\n", err)
			return 1
		}
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
		return 1
	}

	if *outputBase64 {
		fmt.Printf("%s", base64.StdEncoding.EncodeToString(derivedKey))
	} else {
		fmt.Printf("%s", hex.EncodeToString(derivedKey))
	}
	return 0
}
