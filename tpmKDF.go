package tpmkdf

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"slices"

	_ "crypto/sha256"
	_ "crypto/sha512"

	kbkdf "github.com/canonical/go-kbkdf"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpm-kdf/hmac"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get()
	} else {
		return net.Dial("tcp", path)
	}
}

type tpmPrf struct {
	prf
	tpmPath     string
	rwc         io.ReadWriteCloser
	pemkeyBytes []byte
	parentAuth  []byte
	keyAuth     []byte
}

type prf crypto.Hash

func TPMKDF(tpmPath string, rwc io.ReadWriteCloser, pemkeyBytes []byte, parentAuth []byte, keyAuth []byte) (*tpmPrf, error) {

	var irwc io.ReadWriteCloser

	if rwc != nil {
		irwc = rwc
	} else if tpmPath != "" {
		var err error
		irwc, err = OpenTPM(tpmPath)
		if err != nil {
			return nil, err
		}
		defer func() {
			irwc.Close()
		}()
	} else {
		return nil, fmt.Errorf("either tpmPath or readWriteClouser must be specified")
	}

	rwr := transport.FromReadWriter(irwc)

	key, err := keyfile.Decode(pemkeyBytes)
	if err != nil {
		return nil, err
	}

	if len(parentAuth) == 0 {
		parentAuth = nil
	}
	if len(keyAuth) == 0 {
		keyAuth = nil
	}

	// for now just load the ek and use it for encryption.
	// TODO: pass in the hex "name" of the ek to use and compare that to the name derived.
	//       if they match, continue
	createEKRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: createEKRsp.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	encryptionPub, err := tpm2.ReadPublic{
		ObjectHandle: createEKRsp.ObjectHandle,
	}.Execute(rwr)
	if err != nil {
		return nil, err
	}
	ePubName, err := encryptionPub.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	esess, esessloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(createEKRsp.ObjectHandle, *ePubName))
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = esessloser()
	}()

	// now create the H2 primary

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: key.Parent,
			Auth:   tpm2.PasswordAuth(parentAuth),
		},

		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr, esess)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// load the hmac key
	hKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr, esess)
	if err != nil {
		return nil, err
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	return &tpmPrf{
		tpmPath:     tpmPath,
		rwc:         rwc,
		pemkeyBytes: pemkeyBytes,
		parentAuth:  parentAuth,
		keyAuth:     keyAuth,
	}, nil
}

func (p tpmPrf) Size() uint32 {
	return uint32(sha256.Size)
	// return uint32(crypto.Hash(p.prf).Size())
}

func (p tpmPrf) Run(s, x []byte) []byte {
	// h := hmac.New(sha256.New, []byte("my_api_key"))
	// h.Write(x)
	// return h.Sum(nil)

	f, err := hmac.TPMHMAC(p.tpmPath, p.rwc, p.pemkeyBytes, p.parentAuth, p.keyAuth, x)
	if err != nil {
		return nil
	}
	return f
}

func From(tpmPath string, rwc io.ReadWriteCloser, pemkeyBytes []byte, parentAuth []byte, keyAuth []byte) (kbkdf.PRF, error) {
	return TPMKDF(tpmPath, rwc, pemkeyBytes, parentAuth, keyAuth)
}
