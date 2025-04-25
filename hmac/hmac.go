package hmac

import (
	"crypto/rand"
	"io"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

const (
	maxInputBuffer = 1024
)

// TPMHMAC performs HMAC operation for some data.
//
//	tpmPath: path to the TPM (/dev/tpmrm0)
//	pemkey: the PEM formatted TPM private hmac key
//	parentAuth: TPM passphrase auth for the parent
//	keyAuth:  TPM passphrase auth for the hmac key
//	data:  the data to hmac
func TPMHMAC(tpmPath string, pemkey string, parentAuth []byte, keyAuth []byte, data []byte) ([]byte, error) {

	rwc, err := openTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		rwc.Close()
	}()

	rwr := transport.FromReadWriter(rwc)

	c, err := os.ReadFile(pemkey)
	if err != nil {
		return nil, err
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		return nil, err
	}

	if len(parentAuth) == 0 {
		parentAuth = nil
	}
	if len(keyAuth) == 0 {
		keyAuth = nil
	}

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: key.Parent,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	hKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(parentAuth),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	numBytes := 32
	randomBytes := make([]byte, numBytes)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	objAuth := &tpm2.TPM2BAuth{
		Buffer: randomBytes,
	}

	var sas tpm2.Session
	var sasCloser func() error

	if keyAuth != nil {
		sas, sasCloser, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth(keyAuth)}...)
		if err != nil {
			return nil, err
		}

		_, err = tpm2.PolicyAuthValue{
			PolicySession: sas.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
	} else {
		sas, sasCloser, err = tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(keyAuth))
		if err != nil {
			return nil, err
		}
	}

	defer func() {
		_ = sasCloser()
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: hKey.ObjectHandle,
			Name:   hKey.Name,
			Auth:   sas,
		},
		Auth:    *objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   hKey.Name,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
