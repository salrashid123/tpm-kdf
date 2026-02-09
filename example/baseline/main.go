package main

import (
	"crypto"
	"crypto/hmac"
	"fmt"

	_ "crypto/sha256"

	kbkdf "github.com/canonical/go-kbkdf"
)

type prf crypto.Hash

func (p prf) Size() uint32 {
	return uint32(crypto.Hash(p).Size())
}

func (p prf) Run(s, x []byte) []byte {
	s = []byte("my_api_key")
	h := hmac.New(crypto.Hash(p).New, s)
	h.Write(x)
	return h.Sum(nil)
}

// From creates a PRF from the supplied digest algorithm.
func From(alg crypto.Hash) kbkdf.PRF {
	return prf(alg)
}

func main() {

	masterSecret := []byte("my_api_key")

	label := []byte("foo")
	context := []byte("context")

	keyLengthBits := uint32(256)

	// Derive the key using the Counter Mode KDF
	derivedKey := kbkdf.CounterModeKey(
		From(crypto.SHA256), // The pseudorandom function (HMAC-SHA256)
		masterSecret,        // The master secret key
		label,               // Optional label
		context,             // Optional context
		keyLengthBits,       // Desired key length in bits
	)

	fmt.Printf("Derived Key (%d bytes): %x\n", len(derivedKey), derivedKey)
}
