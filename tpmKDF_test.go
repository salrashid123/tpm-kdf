package tpmkdf

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"

	kbkdf "github.com/canonical/go-kbkdf"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmpolicy "github.com/salrashid123/tpm-kdf/policy"
	"github.com/stretchr/testify/require"
)

const (
	swTPMPath = "127.0.0.1:2321"
)

func loadKey(rwr transport.TPM, hmacSensitive []byte, parentPassword []byte, keyPassword []byte) (tpm2.TPMHandle, tpm2.TPM2BPublic, tpm2.TPM2BPrivate, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},

		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: parentPassword,
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	sv := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, sv)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}

	privHash := crypto.SHA256.New()
	_, err = privHash.Write(sv)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}
	_, err = privHash.Write(hmacSensitive)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}

	authValue := tpm2.TPM2BDigest{}
	if keyPassword != nil {
		sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
		if err != nil {
			return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
		}
		defer func() {
			cleanup1()
		}()

		_, err = tpm2.PolicyAuthValue{
			PolicySession: sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
		}

		pgd, err := tpm2.PolicyGetDigest{
			PolicySession: sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
		}
		authValue = pgd.PolicyDigest
	}

	hmacTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            false,
			FixedParent:         false,
			SensitiveDataOrigin: false,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		AuthPolicy: authValue,
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						}),
				},
			}),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BDigest{
				Buffer: privHash.Sum(nil),
			},
		),
	}

	sens2B := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		AuthValue: tpm2.TPM2BAuth{
			Buffer: keyPassword,
		},
		SeedValue: tpm2.TPM2BDigest{
			Buffer: sv,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPM2BSensitiveData{Buffer: hmacSensitive},
		),
	})

	l := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})

	importResponse, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
			Auth:   tpm2.PasswordAuth(parentPassword),
		},
		ObjectPublic: tpm2.New2B(hmacTemplate),
		Duplicate:    tpm2.TPM2BPrivate{Buffer: l},
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}

	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(parentPassword),
		},
		InPublic:  tpm2.New2B(hmacTemplate),
		InPrivate: importResponse.OutPrivate,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	pub, err := tpm2.ReadPublic{
		ObjectHandle: hmacKey.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return 0, tpm2.TPM2BPublic{}, tpm2.TPM2BPrivate{}, tpm2.TPM2BName{}, nil, err
	}

	closer := func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}

	return hmacKey.ObjectHandle, tpm2.New2B(hmacTemplate), importResponse.OutPrivate, pub.Name, closer, nil
}

type prf crypto.Hash

func (p prf) Size() uint32 {
	return uint32(crypto.Hash(p).Size())
}

func (p prf) Run(s, x []byte) []byte {
	h := hmac.New(crypto.Hash(p).New, s)
	h.Write(x)
	return h.Sum(nil)
}

// From creates a PRF from the supplied digest algorithm.
func From(alg crypto.Hash) kbkdf.PRF {
	return prf(alg)
}

func TestKDFBasic(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	masterSecret := []byte("my_api_key")

	label := []byte("foo")
	context := []byte("context")

	keyLengthBits := uint32(256)

	// Derive the key using the Counter Mode KDF
	derivedKeyBase := kbkdf.CounterModeKey(
		From(crypto.SHA256), // The pseudorandom function (HMAC-SHA256)
		masterSecret,        // The master secret key
		label,               // Optional label
		context,             // Optional context
		keyLengthBits,       // Desired key length in bits
	)

	//t.Logf("(%d bytes): %x\n", len(derivedKeyBase), derivedKeyBase)

	rwr := transport.FromReadWriter(tpmDevice)

	_, pu, pr, _, closer, err := loadKey(rwr, masterSecret, nil, nil)
	require.NoError(t, err)
	closer()

	kf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: false,
		Parent:    tpm2.TPMHandle(tpm2.TPMRHOwner.HandleValue()),
		Pubkey:    pu,
		Privkey:   pr,
	}
	require.NoError(t, err)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	require.NoError(t, err)

	prf, err := NewTPMPRF("", tpmDevice, keyFileBytes.Bytes(), tpmpolicy.H2, nil, nil, "")
	require.NoError(t, err)

	// Derive the key using the Counter Mode KDF
	derivedKey, err := CounterModeKey(
		prf,           // The pseudorandom function (HMAC-SHA256)
		nil,           // The master secret key
		label,         // Optional label
		context,       // Optional context
		keyLengthBits, // Desired key length in bits
	)
	require.NoError(t, err)
	//t.Logf("(%d bytes): %x\n", len(derivedKey), derivedKey)
	require.True(t, bytes.Equal(derivedKeyBase, derivedKey))

}

func TestNISTVector(t *testing.T) {

	// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Key-Derivation

	// [PRF=HMAC_SHA256]
	// [CTRLOCATION=BEFORE_FIXED]
	// [RLEN=32_BITS]

	// COUNT=0
	// L = 128
	// KI = dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0
	// FixedInputDataByteLen = 60
	// FixedInputData = 01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac
	// 	Binary rep of i = 00000001
	// 	instring = 0000000101322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac
	// KO = 10621342bfb0fd40046c0e29f2cfdbf0

	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	masterSecret, err := hex.DecodeString("dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0")
	require.NoError(t, err)
	fixed, err := hex.DecodeString("01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac")
	require.NoError(t, err)

	expected, err := hex.DecodeString("10621342bfb0fd40046c0e29f2cfdbf0")
	require.NoError(t, err)

	//t.Logf("(%d bytes): %x\n", len(derivedKeyBase), derivedKeyBase)

	rwr := transport.FromReadWriter(tpmDevice)

	_, pu, pr, _, closer, err := loadKey(rwr, masterSecret, nil, nil)
	require.NoError(t, err)
	closer()

	kf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: false,
		Parent:    tpm2.TPMHandle(tpm2.TPMRHOwner.HandleValue()),
		Pubkey:    pu,
		Privkey:   pr,
	}
	require.NoError(t, err)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	require.NoError(t, err)

	prf, err := NewTPMPRF("", tpmDevice, keyFileBytes.Bytes(), tpmpolicy.H2, nil, nil, "")
	require.NoError(t, err)

	derivedKey, err := counterModeKeyInternal(prf, masterSecret, fixed, 128)
	require.NoError(t, err)

	//t.Logf("(%d bytes): %x\n", len(derivedKey), derivedKey)
	require.True(t, bytes.Equal(expected, derivedKey))

}

func TestKDFKeyAuth(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	masterSecret := []byte("my_api_key")
	keyPassword := []byte("mypassword")
	_, pu, pr, _, closer, err := loadKey(rwr, masterSecret, nil, keyPassword)
	require.NoError(t, err)
	closer()

	kf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: false,
		Parent:    tpm2.TPMHandle(tpm2.TPMRHOwner.HandleValue()),
		Pubkey:    pu,
		Privkey:   pr,
	}
	require.NoError(t, err)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	require.NoError(t, err)

	label := []byte("foo")
	context := []byte("context")
	keyLengthBits := uint32(256)

	// Derive the key using the Counter Mode KDF
	derivedKeyBase := kbkdf.CounterModeKey(
		From(crypto.SHA256), // The pseudorandom function (HMAC-SHA256)
		masterSecret,        // The master secret key
		label,               // Optional label
		context,             // Optional context
		keyLengthBits,       // Desired key length in bits
	)

	p, err := tpmpolicy.NewPasswordAuthSession(rwr, keyPassword, 0)
	require.NoError(t, err)

	prf, err := NewTPMPRF("", tpmDevice, keyFileBytes.Bytes(), tpmpolicy.H2, nil, p, "")
	require.NoError(t, err)

	// Derive the key using the Counter Mode KDF
	derivedKey, err := CounterModeKey(
		prf,           // The pseudorandom function (HMAC-SHA256)
		nil,           // The master secret key
		label,         // Optional label
		context,       // Optional context
		keyLengthBits, // Desired key length in bits
	)
	require.NoError(t, err)
	//t.Logf("(%d bytes): %x\n", len(derivedKey), derivedKey)
	require.True(t, bytes.Equal(derivedKeyBase, derivedKey))
}

func TestKDFParentAuth(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	masterSecret := []byte("my_api_key")
	parentPassword := []byte("mypassword")
	rwr := transport.FromReadWriter(tpmDevice)

	_, pu, pr, _, closer, err := loadKey(rwr, masterSecret, parentPassword, nil)
	require.NoError(t, err)
	closer()

	kf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: true,
		Parent:    tpm2.TPMHandle(tpm2.TPMRHOwner.HandleValue()),
		Pubkey:    pu,
		Privkey:   pr,
	}
	require.NoError(t, err)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	require.NoError(t, err)

	prf, err := NewTPMPRF("", tpmDevice, keyFileBytes.Bytes(), tpmpolicy.H2, parentPassword, nil, "")
	require.NoError(t, err)

	label := []byte("foo")
	context := []byte("context")
	keyLengthBits := uint32(256)

	// Derive the key using the Counter Mode KDF
	derivedKeyBase := kbkdf.CounterModeKey(
		From(crypto.SHA256), // The pseudorandom function (HMAC-SHA256)
		masterSecret,        // The master secret key
		label,               // Optional label
		context,             // Optional context
		keyLengthBits,       // Desired key length in bits
	)

	// Derive the key using the Counter Mode KDF
	derivedKey, err := CounterModeKey(
		prf,           // The pseudorandom function (HMAC-SHA256)
		nil,           // The master secret key
		label,         // Optional label
		context,       // Optional context
		keyLengthBits, // Desired key length in bits
	)
	require.NoError(t, err)
	//t.Logf("(%d bytes): %x\n", len(derivedKey), derivedKey)
	require.True(t, bytes.Equal(derivedKeyBase, derivedKey))

	// now reset the password back

	// _, err = tpm2.HierarchyChangeAuth{
	// 	AuthHandle: tpm2.AuthHandle{
	// 		Handle: tpm2.TPMRHOwner,
	// 		Auth:   tpm2.PasswordAuth(parentPassword),
	// 	},
	// 	NewAuth: tpm2.TPM2BAuth{
	// 		Buffer: []byte(""),
	// 	},
	// }.Execute(rwr)
	// require.NoError(t, err)

}
