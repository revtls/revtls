package x509

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"
)

type DDC struct {
	Id                  string
	RawTBSDDC           []byte
	NotBefore, NotAfter time.Time // Validity bounds.
	DelegatedKeys       []DelegatedKey
	Signature           []byte
	// Sig_r *big.Int
	// Sig_s *big.Int
}

func CreateDomainOwnerRDC(rand io.Reader, template *DDC, domainOwner *Certificate, pub, priv interface{}) (*DDC, error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	if template.Id == "" {
		return nil, errors.New("x509: no Id given")
	}

	hashFunc, _, err := signingParamsForPublicKey(key.Public(), 0)
	if err != nil {
		log.Fatal(hashFunc)
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	// Check that the signer's public key matches the private key, if available.
	type privateKey interface {
		Equal(crypto.PublicKey) bool
	}
	if privPub, ok := key.Public().(privateKey); !ok {
		return nil, errors.New("x509: internal error: supported public key does not implement Equal")
	} else if domainOwner.PublicKey != nil && !privPub.Equal(domainOwner.PublicKey) {
		return nil, errors.New("x509: provided PrivateKey doesn't match parent's PublicKey")
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}

	pubkey := pub.(*ecdsa.PublicKey)
	template.DelegatedKeys[0].KeyID = "#key0"
	template.DelegatedKeys[0].Role = "Cache"
	template.DelegatedKeys[0].Description = "More info on cdn1.com/caching"
	template.DelegatedKeys[0].PublicKeyInfo = publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey}
	template.DelegatedKeys[0].PublicKeyRaw = pubkey

	tbsDDCContents, err := json.Marshal(template)
	if err != nil {
		return nil, err
	}

	template.RawTBSDDC = tbsDDCContents
	signed := tbsDDCContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	//digest := sha256.Sum256(template.RawTBSDDC)
	var signErr error
	//sig_r, sig_s, signErr := ecdsa.Sign(rand, priv.(*ecdsa.PrivateKey), digest[:])
	signature, signErr := ecdsa.SignASN1(rand, priv.(*ecdsa.PrivateKey), signed /*digest[:]*/)
	template.Signature = signature
	// template.Sig_r = sig_r
	// template.Sig_s = sig_s
	if signErr != nil {
		return nil, fmt.Errorf("DDC ERROR")
	}

	//verifyErr := ecdsa.Verify(&priv.(*ecdsa.PrivateKey).PublicKey, digest[:], template.Sig_r, template.Sig_s)
	verifyErr := ecdsa.VerifyASN1(&priv.(*ecdsa.PrivateKey).PublicKey, signed /*digest[:]*/, template.Signature)
	if verifyErr != true {
		return nil, fmt.Errorf("DDC Verify Error")
	}

	return template, nil
}

func CreateDomainOwnerAndMiddleboxDDC(rand io.Reader, template *DDC, domainOwner *Certificate, pub, priv interface{}, rsapub *ecdsa.PublicKey, numOfMb int, numOfKey int) (*DDC, error) {
	key, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	if template.Id == "" {
		return nil, errors.New("x509: no Id given")
	}

	hashFunc, _, err := signingParamsForPublicKey(key.Public(), 0)
	if err != nil {
		log.Fatal(hashFunc)
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	// Check that the signer's public key matches the private key, if available.
	type privateKey interface {
		Equal(crypto.PublicKey) bool
	}
	if privPub, ok := key.Public().(privateKey); !ok {
		return nil, errors.New("x509: internal error: supported public key does not implement Equal")
	} else if domainOwner.PublicKey != nil && !privPub.Equal(domainOwner.PublicKey) {
		return nil, errors.New("x509: provided PrivateKey doesn't match parent's PublicKey")
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}

	//All MBs use same key and info for the performance test purpose
	index := 0

	for index < numOfKey {
		template.DelegatedKeys[index].KeyID = "#key" + strconv.Itoa(index)
		template.DelegatedKeys[index].Role = "Cache"
		template.DelegatedKeys[index].Description = "More info on cdn1.com/caching"
		template.DelegatedKeys[index].PublicKeyInfo = publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey}
		template.DelegatedKeys[index].PublicKeyRaw = rsapub
		index++
	}

	tbsDDCContents, err := json.Marshal(template)
	if err != nil {
		return nil, err
	}
	template.RawTBSDDC = tbsDDCContents

	signed := tbsDDCContents
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	//digest := sha256.Sum256(template.RawTBSDDC)
	var signErr error
	//sig_r, sig_s, signErr := ecdsa.Sign(rand, priv.(*ecdsa.PrivateKey), digest[:])
	signature, signErr := ecdsa.SignASN1(rand, priv.(*ecdsa.PrivateKey), signed /*digest[:]*/)
	template.Signature = signature
	// template.Sig_r = sig_r
	// template.Sig_s = sig_s
	if signErr != nil {
		return nil, fmt.Errorf("DDC ERROR")
	}

	//verifyErr := ecdsa.Verify(&priv.(*ecdsa.PrivateKey).PublicKey, digest[:], template.Sig_r, template.Sig_s)
	verifyErr := ecdsa.VerifyASN1(&priv.(*ecdsa.PrivateKey).PublicKey, signed /*digest[:]*/, template.Signature)
	if verifyErr != true {
		return nil, fmt.Errorf("DDC Verify Error")
	}

	return template, nil
}
