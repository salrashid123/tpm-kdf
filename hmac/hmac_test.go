package hmac

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/stretchr/testify/require"
)

var ()

func loadKey(rwr transport.TPM, hmacSensitive []byte, parentPassword []byte, keyPassword []byte) (tpm2.TPMHandle, tpm2.TPM2BPublic, tpm2.TPM2BPrivate, tpm2.TPM2BName, func(), error) {

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(parentPassword),
		},

		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
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
			Auth:   tpm2.PasswordAuth(nil),
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
			Auth:   tpm2.PasswordAuth(nil),
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

func TestHMAC(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	k := []byte("my_api_key")
	_, pu, pr, _, closer, err := loadKey(rwr, k, nil, nil)
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

	x := []byte("foo")

	f, err := TPMHMAC("", tpmDevice, keyFileBytes.Bytes(), nil, nil, false, x)
	require.NoError(t, err)

	hmacInstance := hmac.New(sha256.New, k)
	hmacInstance.Write(x)
	signature := hmacInstance.Sum(nil)

	require.Equal(t, f, signature)
}
