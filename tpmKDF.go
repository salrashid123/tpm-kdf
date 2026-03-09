package tpmkdf

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	tpmhmac "github.com/salrashid123/tpm-kdf/hmac"
	tpmpolicy "github.com/salrashid123/tpm-kdf/policy"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

// NOTE:  the core code here is from https://github.com/canonical/go-kbkdf

type tprf struct {
	tpmPath               string
	rwc                   io.ReadWriteCloser
	pemKeyBytes           []byte
	parentKeyType         tpmpolicy.KeyType
	parentAuth            []byte
	AuthSession           tpmpolicy.Session // If the key needs a session, supply one as the `tpmkdf.Session`
	sessionEncryptionName string
	h                     crypto.Hash
}

type PRF interface {
	// Size returns the output length of this PRF.
	Size() uint32

	// Run computes bytes for the supplied seed and input value.
	Run(s, x []byte) ([]byte, error)
}

func (p tprf) Size() uint32 {
	return uint32(p.h.Size())
}

func (p tprf) Run(s, x []byte) ([]byte, error) {
	f, err := tpmhmac.TPMHMAC(p.tpmPath, p.rwc, p.pemKeyBytes, p.parentKeyType, p.parentAuth, p.AuthSession, p.sessionEncryptionName, x)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// From creates a PRF from the supplied digest algorithm.
func NewTPMPRF(tpmPath string, rwc io.ReadWriteCloser, pemkeyBytes []byte, parentKeyType tpmpolicy.KeyType, parentAuth []byte, session tpmpolicy.Session, sessionEncryptionName string) (PRF, error) {

	key, err := keyfile.Decode(pemkeyBytes)
	if err != nil {
		return nil, err
	}
	pub := key.Pubkey

	pubid, err := pub.Contents()
	if err != nil {
		return nil, err
	}
	var h crypto.Hash
	switch pubid.Type {
	case tpm2.TPMAlgKeyedHash:
		hkDetail, err := pubid.Parameters.KeyedHashDetail()
		if err != nil {
			return nil, fmt.Errorf("can't read hmac key details %v", err)
		}
		hd, err := hkDetail.Scheme.Details.HMAC()
		if err != nil {
			return nil, fmt.Errorf("can't read key Scheme.Details.HMAC() %v", err)
		}

		h, err = hd.HashAlg.Hash()
		if err != nil {
			return nil, fmt.Errorf("can't read key hash type %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type %v", pubid.Type)
	}
	return tprf{tpmPath, rwc, pemkeyBytes, parentKeyType, parentAuth, session, sessionEncryptionName, h}, nil
}

func fixedBytes(label, context []byte, bitLength uint32) []byte {
	var res bytes.Buffer
	res.Write(label)
	res.Write([]byte{0})
	res.Write(context)
	binary.Write(&res, binary.BigEndian, bitLength)
	return res.Bytes()
}

func commonKDF(prfLen uint32, bitLength uint32, fn func(uint32) ([]byte, error)) ([]byte, error) {
	n := (bitLength + prfLen - 1) / prfLen // The number of iterations required

	var res bytes.Buffer
	var err error
	for i := uint32(1); i <= n; i++ {
		x, err := fn(i)
		if err != nil {
			return nil, err
		}
		res.Write(x)
	}

	return res.Bytes()[:(bitLength+7)/8], err
}

func counterModeKeyInternal(prf PRF, key, fixed []byte, bitLength uint32) ([]byte, error) {
	return commonKDF(prf.Size(), bitLength, func(i uint32) ([]byte, error) {
		var x bytes.Buffer
		binary.Write(&x, binary.BigEndian, i)
		x.Write(fixed)
		return prf.Run(key, x.Bytes())
	})
}

// CounterModeKey derives a key of the specified length using the counter mode
// function described in NIST SP-800-108, using the supplied PRF, secret key and
// other input parameters.
func CounterModeKey(prf PRF, key, label, context []byte, bitLength uint32) ([]byte, error) {
	return counterModeKeyInternal(prf, key, fixedBytes(label, context, bitLength), bitLength)
}
