package certandrdcgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

// Return the root CA's certificate template and keys to create
// the domain owner's certificate
func LocalCreateRootCertificate(subjectAltName string) (*x509.Certificate, *rsa.PrivateKey) {
	//privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Issuer: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Alice CA Inc"},
			OrganizationalUnit: []string{"Alice CA Admin"},
			CommonName:         "Alice Root CA",
		},
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Alice CA Inc"},
			OrganizationalUnit: []string{"Alice CA Admin"},
			CommonName:         "Alice Root CA",
		},
		DNSNames:  []string{subjectAltName},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(8760 * time.Hour),
		IsCA:      true,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatal("Failed to encode certificate to PEM")
	}
	if err := os.WriteFile("localRootCACert.pem", pemCert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a local root cert.pem\n")

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		log.Fatal("Failed to encode key to PEM")
	}
	if err := os.WriteFile("localRootCAKey.pem", pemKey, 0600); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a local root CA key.pem\n")

	return &template, privateKey
}

func LocalCreateDomainOwnerCertificate(subjectAltName string, privateKey *rsa.PrivateKey, rootTemplate x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	domainOwnerPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//domainOwnerPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Issuer: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Alice CA Inc"},
			OrganizationalUnit: []string{"Alice CA Admin"},
			CommonName:         "Alice Root CA",
		},
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Domain Owner Inc"},
			OrganizationalUnit: []string{"Domain Owner Admin"},
			CommonName:         "Domain Owner",
		},
		DNSNames: []string{subjectAltName},
		//For remote evaluation
		//IPAddresses: []net.IP{net.IPv4(10, 0, 0, 30)},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(8760 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &rootTemplate, &domainOwnerPrivateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatal("Failed to encode certificate to PEM")
	}
	if err := os.WriteFile("localDomainOwnerCert.pem", pemCert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a localDomainOwnerCert.pem\n")

	privBytes, err := x509.MarshalPKCS8PrivateKey(domainOwnerPrivateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		log.Fatal("Failed to encode key to PEM")
	}
	if err := os.WriteFile("localDomainOwnerKey.pem", pemKey, 0600); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a localDomainOwnerKey.pem\n")

	return &template, domainOwnerPrivateKey
}

func LocalCreateDomainOwnerRDC(privateKey *ecdsa.PrivateKey, domainOwnerTemplate x509.Certificate) {
	domainOwnerDDCPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//domainOwnerDDCPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.DDC{
		Id:        "cdn1",
		NotBefore: domainOwnerTemplate.NotBefore,
		NotAfter:  domainOwnerTemplate.NotAfter,
		DelegatedKeys: []x509.DelegatedKey{
			{},
		},
	}

	jsonBytes, err := x509.CreateDomainOwnerRDC(rand.Reader, &template, &domainOwnerTemplate, &domainOwnerDDCPrivateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to finish CreateDomainOwnerDDC: %v", err)
	}

	jsonCert, err := json.Marshal(jsonBytes)
	if err != nil {
		log.Fatalf("Failed to create json ertificate: %v", err)
	}
	if err := os.WriteFile("localDomainOwnerRDC.json", jsonCert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a local domainOwnerRDC.json\n")

	privBytes, err := x509.MarshalPKCS8PrivateKey(domainOwnerDDCPrivateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		log.Fatal("Failed to encode key to PEM")
	}
	if err := os.WriteFile("localDomainOwnerRDCKey.pem", pemKey, 0600); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a local domainOwnerRDCKey.pem\n")
}

func LocalCreateDomainOwnerAndMiddleboxDDC(privateKey *ecdsa.PrivateKey, domainOwnerTemplate x509.Certificate, numOfMb int, numOfKey int) {
	middleboxDDCPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//middleboxDDCPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.DDC{
		Id:            "cdn1",
		NotBefore:     domainOwnerTemplate.NotBefore,
		NotAfter:      domainOwnerTemplate.NotAfter,
		DelegatedKeys: make([]x509.DelegatedKey, numOfKey, 50),
	}
	jsonBytes, err := x509.CreateDomainOwnerAndMiddleboxDDC(rand.Reader, &template, &domainOwnerTemplate, &middleboxDDCPrivateKey.PublicKey, privateKey, &middleboxDDCPrivateKey.PublicKey, numOfMb, numOfKey)
	if err != nil {
		log.Fatalf("Failed to finish MiddleBoxDDC: %v", err)
	}

	jsonCert, err := json.Marshal(jsonBytes)
	if err != nil {
		log.Fatalf("Failed to create json ertificate: %v", err)
	}
	if err := os.WriteFile("localMiddleboxDDC.json", jsonCert, 0644); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote a localMiddleboxDDC.json\n")

	privBytes, err := x509.MarshalPKCS8PrivateKey(middleboxDDCPrivateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		log.Fatal("Failed to encode key to PEM")
	}
	if err := os.WriteFile("localMiddleboxDDCKey.pem", pemKey, 0600); err != nil {
		log.Fatal(err)
	}
	log.Print("wrote localMiddleboxDDCKey.pem\n")

}
