package hmac

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmpolicy "github.com/salrashid123/tpm-kdf/policy"
	tpmutil "github.com/salrashid123/tpm-kdf/util"
)

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
func TPMHMAC(tpmPath string, rwc io.ReadWriteCloser, pemkeyBytes []byte, parentAuth []byte, session tpmpolicy.Session, sessionEncryptionName string, data []byte) ([]byte, error) {

	var irwc io.ReadWriteCloser

	if rwc != nil {
		irwc = rwc
	} else if tpmPath != "" {
		var err error
		irwc, err = tpmutil.OpenTPM(tpmPath)
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

	var esess tpm2.Session
	var esessloser func() error

	//create a default rsaek key for session encryption
	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}
	createEKRsp, err := createEKCmd.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("an't acquire acquire rsaek %v", err)
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

	// compare that to what the user specified, if any
	if sessionEncryptionName != "" {
		if sessionEncryptionName != hex.EncodeToString(createEKRsp.Name.Buffer) {
			return nil, fmt.Errorf("session encryption name mismatch: got [%s]   expected [%s]", sessionEncryptionName, hex.EncodeToString(createEKRsp.Name.Buffer))
		}
		esess, esessloser, err = tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ePubName))
		if err != nil {
			return nil, err
		}
	} else {
		esess, esessloser, err = tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(nil), tpm2.AESEncryption(128, tpm2.EncryptInOut), tpm2.Salted(createEKRsp.ObjectHandle, *ePubName))
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		_ = esessloser()
	}()

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: key.Parent,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: parentAuth,
				},
			},
		},
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

	hKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth(parentAuth),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr, esess)
	if err != nil {
		return nil, err
	}

	// flush the primary; its no longer needed
	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

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
	if session != nil {
		sas, sasCloser, err = session.GetSession()
		if err != nil {
			return nil, err
		}
	} else {
		sas, sasCloser, err = tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(nil), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(createEKRsp.ObjectHandle, *ePubName))
		if err != nil {
			return nil, err
		}
	}
	defer sasCloser()

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

	rspSC, err := sequenceComplete.Execute(rwr, esess)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
