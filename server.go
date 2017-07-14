package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
)

const (
	KeySize       = 2048
	RSAPublicFile = "key.pem.pub"
)

// generate RSA keys
func generateRSAKeys(writeInFile bool) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	var publicKey *rsa.PublicKey

	privateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, nil, err
	}
	publicKey = &privateKey.PublicKey

	if writeInFile {
		var RSAPrivateFile string = "key.pem"

		err = func(privateKey *rsa.PrivateKey, keyfile string) error {
			file, err := os.OpenFile(keyfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
			if err != nil {
				return err
			}
			defer file.Close()

			privateBlock := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			}
			// writing private key in file
			pem.Encode(file, privateBlock)

			return nil
		}(privateKey, RSAPrivateFile)
	}

	return publicKey, privateKey, err
}

// parse public key to pem format
func PublicKeytoPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	publicKey := privateKey.PublicKey

	bytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return []byte(""), nil
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}

	return pem.EncodeToMemory(block), nil
}

func PEMtoRSAPublic(p []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("Error getting RSA block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Error getting public key")
	}

	return pub, nil
}

func main() {
	_, private, err := generateRSAKeys(false)
	if err != nil {
		panic(err)
	}

	pem, err := PublicKeytoPEM(private)
	if err != nil {
		panic(err)
	}

	ln, err := net.Listen("tcp", ":1025")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	pem2 := make([]byte, 2048)
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		fmt.Println("Connected with:", conn.RemoteAddr().String())

		conn.Write(pem)

		n, err := conn.Read(pem2)
		if err != nil {
			panic(err)
		}

		fmt.Println(string(pem2[:n]))
		public2, err := PEMtoRSAPublic(pem2[:n])
		if err != nil {
			panic(err)
		}

		msg, err := rsa.EncryptPKCS1v15(rand.Reader, public2, []byte("hello man"))
		if err != nil {
			panic(err)
		}

		conn.Write(msg)

		b := make([]byte, 256)
		n, err = conn.Read(b)
		if err != nil {
			panic(err)
		}

		bytes, err := rsa.DecryptPKCS1v15(rand.Reader, private, b[:n])
		if err != nil {
			panic(err)
		}
		fmt.Println(string(bytes))

		conn.Close()
	}
}
