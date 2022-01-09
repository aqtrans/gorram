package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	"git.jba.io/go/gorram/proto"
)

type Gorram struct {
	ClientCfgs sync.Map
	//cfg              serverConfig
	connectedClients clients
	alertsMap        alerts
}

type clients struct {
	sync.Mutex
	m proto.ClientList
}

type alerts struct {
	sync.Mutex
	m map[string]*proto.Alert
}

func (g *Gorram) Hello(clientName string, resp *string) error {

	log.Println(clientName, "connected!")

	*resp = "omg"

	return nil
}

func VerifySignature(pubKey rsa.PublicKey, message, signature string) bool {
	msgHash := sha256.New()
	_, err := msgHash.Write([]byte(message))
	if err != nil {
		log.Println("error hashing message", err)
		return false
	}
	msgHashSum := msgHash.Sum(nil)

	decodedSig, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		log.Println("error decoding signature from base64", err)
		return false
	}

	// VerifyPSS returns err if verification fails
	err = rsa.VerifyPSS(&pubKey, crypto.SHA256, msgHashSum, decodedSig, nil)
	if err != nil {
		log.Println("error verifying signature:", err)
		return false
	}

	return true
}

func SignSignature(privKey rsa.PrivateKey, message string) string {
	/*
		block, _ := pem.Decode(rawPrivKey)
		if block == nil {
			fmt.Println("Invalid PEM Block")
			return ""
		}

		privateKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			fmt.Println(err)
			return ""
		}

		var ed25519Key ed25519.PrivateKey
		var ok bool
		if ed25519Key, ok = privateKey.(ed25519.PrivateKey); !ok {
			log.Println("key is the wrong type", privateKey)
			return ""
		}

		if len(ed25519Key) != ed25519.PrivateKeySize {
			log.Println("invalid key size")
			return ""
		}
	*/

	var err error
	msgHash := sha256.New()
	_, err = msgHash.Write([]byte(message))
	if err != nil {
		log.Println("error hashing message", err)
		return ""
	}
	msgHashSum := msgHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, &privKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		log.Println("error signing message", err)
		return ""
	}

	encodedSig := base64.URLEncoding.EncodeToString(signature)

	return encodedSig
}

func LoadPublicKey(name string) *rsa.PublicKey {
	pubKey, err := ioutil.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to load key %s: %v", name, err))
	}

	pubKeyDec, err := base64.URLEncoding.DecodeString(string(pubKey))
	if err != nil {
		log.Println("error decoding pubkey", err)
		return nil
	}

	pubKeyParsed, err := x509.ParsePKCS1PublicKey(pubKeyDec)
	if err != nil {
		log.Println("error parsing pubkey", err)
		return nil
	}

	return pubKeyParsed
}

func LoadPrivateKey(name string) *rsa.PrivateKey {
	privKey, err := ioutil.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to load key %s: %v", name, err))
	}

	privKeyDec, err := base64.URLEncoding.DecodeString(string(privKey))
	if err != nil {
		log.Println("error decoding private key", err)
		return nil
	}

	privKeyParsed, err := x509.ParsePKCS1PrivateKey(privKeyDec)
	if err != nil {
		log.Println("error parsing private key", err)
		return nil
	}

	return privKeyParsed
}

func ParsePublicKey(pubKey string) *rsa.PublicKey {

	pubKeyDec, err := base64.URLEncoding.DecodeString(pubKey)
	if err != nil {
		log.Println("error decoding pubkey", err)
		return nil
	}

	pemBlock, _ := pem.Decode(pubKeyDec)

	pubKeyParsed, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		log.Println("error parsing pubkey", err)
		return nil
	}

	return pubKeyParsed
}

func ParsePrivateKey(privKey string) *rsa.PrivateKey {

	privKeyDecoded, err := base64.URLEncoding.DecodeString(privKey)
	if err != nil {
		log.Println("error decoding private key from base64", err)
		return nil
	}

	pemBlock, _ := pem.Decode(privKeyDecoded)

	privKeyParsed, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Println("error parsing private key", err)
		return nil
	}

	return privKeyParsed
}

func GenerateKeys() (public, private string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalln("error generating RSA keys", err)
	}

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	if privPem == nil {
		log.Println("private key unable to be encoded")
		return
	}

	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey),
	})
	if pubPem == nil {
		log.Println("public key unable to be encoded")
		return
	}

	pubEnc := base64.URLEncoding.EncodeToString(pubPem)
	privEnc := base64.URLEncoding.EncodeToString(privPem)
	/*
		err = ioutil.WriteFile("homer.pub", []byte(pubEnc), 0644)
		if err != nil {
			log.Fatalln("error writing pub key", err)
		}
		err = ioutil.WriteFile("homer.key", []byte(privEnc), 0644)
		if err != nil {
			log.Fatalln("error writing priv key", err)
		}
	*/
	return pubEnc, privEnc
}

func Encrypt(pubKey *rsa.PublicKey, messageBytes []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, messageBytes, nil)
	if err != nil {
		log.Println("error encrypting message", err)
		return nil
	}
	return encryptedBytes
}

func Decrypt(privKey *rsa.PrivateKey, encryptedBytes []byte) []byte {
	decryptedBytes, err := privKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		log.Println("error decrypting message", err)
		return nil
	}
	return decryptedBytes
}
