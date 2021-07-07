// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Based heavily on https://golang.org/src/crypto/tls/generate_cert.go, this generates CA, server, and client TLS certificates for use in gRPC

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// GenerateCACert generates and saves a CA cert to cacert.pem and cacert.key
func GenerateCACert(sslPath string) {
	certPath := filepath.Join(sslPath, "cacert.pem")
	certKeyPath := filepath.Join(sslPath, "cacert.key")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(36500 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gorram Monitoring CA"},
			CommonName:   "Gorram CA",
		},
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certPath, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Println("written", certPath)

	keyOut, err := os.OpenFile(certKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certKeyPath, err)
	}
	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()
	log.Println("written", certKeyPath)
}

// GenerateServerCert generates a server certificate against a given CA cert
func GenerateServerCert(hosts []string, sslPath string) tls.Certificate {
	caCertPath := filepath.Join(sslPath, "cacert.pem")
	caCertKeyPath := filepath.Join(sslPath, "cacert.key")

	ca, err := tls.LoadX509KeyPair(caCertPath, caCertKeyPath)
	if err != nil {
		log.Fatalln("Error parsing cacert.pem/key", err)
	}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		log.Fatalln("Error parsing cacert.pem:", err)
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(36500 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gorram Monitoring server"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	//hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, pk.Public(), ca.PrivateKey)
	if err != nil {
		log.Fatalln("Error creating server cert:", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  pk,
	}
}

// SaveServerCert generates and saves a server cert
func SaveServerCert(hosts []string, sslPath string) {
	//caCertPath := filepath.Join(sslPath, "cacert.pem")
	//caCertKeyPath := filepath.Join(sslPath, "cacert.key")

	certPath := filepath.Join(sslPath, "server.pem")
	certKeyPath := filepath.Join(sslPath, "server.key")

	cert := GenerateServerCert(hosts, sslPath)

	certOut, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certPath, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	certOut.Close()
	log.Println("written", certPath)

	keyOut, err := os.OpenFile(certKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certKeyPath, err)
	}
	pem.Encode(keyOut, pemBlockForKey(cert.PrivateKey))
	keyOut.Close()
	log.Println("written", certKeyPath)
}

// SaveClientCert generates and saves a client cert to disk
func SaveClientCert(hostname, sslPath string) {
	certPath := filepath.Join(sslPath, hostname+".pem")
	certKeyPath := filepath.Join(sslPath, hostname+".key")

	cert := GenerateClientCert(hostname, sslPath)

	certOut, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certPath, err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	certOut.Close()
	log.Println("written", certPath)

	keyOut, err := os.OpenFile(certKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("failed to open %s for writing: %s", certKeyPath, err)
	}
	pem.Encode(keyOut, pemBlockForKey(cert.PrivateKey))
	keyOut.Close()
	log.Println("written", certKeyPath)
}

// GenerateClientCert generates a client cert against a given CA
func GenerateClientCert(clientName, sslPath string) tls.Certificate {
	caCertPath := filepath.Join(sslPath, "cacert.pem")
	caCertKeyPath := filepath.Join(sslPath, "cacert.key")

	ca, err := tls.LoadX509KeyPair(caCertPath, caCertKeyPath)
	if err != nil {
		log.Fatalln("Error loading cacert.pem/key", err)
	}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		log.Fatalln("Error parsing cacert.pem:", err)
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(36500 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gorram Monitoring client"},
			CommonName:   clientName, // Will be checked by the server
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, caCert, pk.Public(), ca.PrivateKey)
	if err != nil {
		log.Fatalln("Error creating client cert:", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  pk,
	}
}
