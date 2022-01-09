package common

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

func VerifySignature(pubKey ed25519.PublicKey, message, signature string) bool {
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

	omg := ed25519.Verify(pubKey, msgHashSum, decodedSig)

	return omg
}

func SignSignature(privKey ed25519.PrivateKey, message string) string {
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

	signature := ed25519.Sign(privKey, msgHashSum)

	encodedSig := base64.URLEncoding.EncodeToString(signature)

	return encodedSig
}

func LoadPublicKey(name string) ed25519.PublicKey {
	pubKey, err := ioutil.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to load key %s: %v", name, err))
	}

	pubKeyDec, err := base64.URLEncoding.DecodeString(string(pubKey))
	if err != nil {
		log.Println("error decoding pubkey", err)
		return nil
	}

	return ed25519.PublicKey(pubKeyDec)
}

func LoadPrivateKey(name string) ed25519.PrivateKey {
	privKey, err := ioutil.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to load key %s: %v", name, err))
	}

	log.Println(name, string(privKey))

	privKeyDec, err := base64.URLEncoding.DecodeString(string(privKey))
	if err != nil {
		log.Println("error decoding pubkey", err)
		return nil
	}

	return ed25519.PrivateKey(privKeyDec)
}

func ParsePublicKey(pubKey string) ed25519.PublicKey {

	pubKeyDec, err := base64.URLEncoding.DecodeString(pubKey)
	if err != nil {
		log.Println("error decoding pubkey", err)
		return nil
	}

	return ed25519.PublicKey(pubKeyDec)
}

func ParsePrivateKey(privKey string) ed25519.PrivateKey {

	privKeyDec, err := base64.URLEncoding.DecodeString(privKey)
	if err != nil {
		log.Println("error decoding pubkey", err)
		return nil
	}

	return ed25519.PrivateKey(privKeyDec)
}

func GenerateKeys() (public, private string) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalln("error generating ed25519 keys", err)
	}
	pubEnc := base64.URLEncoding.EncodeToString(pub)
	privEnc := base64.URLEncoding.EncodeToString(priv)
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
