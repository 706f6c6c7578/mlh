package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/curve25519"
	"filippo.io/edwards25519"
)

func main() {
	pubKeysFile := flag.String("pubkeys", "", "Path to PEM file containing recipient public keys")
	payloadInput := flag.String("payload", "", "Minicrypt payload (base64 string or file path)")
	flag.Parse()

	if *pubKeysFile == "" || *payloadInput == "" {
		flag.Usage()
		os.Exit(1)
	}

	log.Println("Loading public keys from:", *pubKeysFile)
	pubKeys, err := loadPublicKeys(*pubKeysFile)
	if err != nil {
		log.Fatalf("Failed loading public keys: %v", err)
	}

	log.Println("Processing payload input:", *payloadInput)
	encryptedPayload, err := readPayload(*payloadInput)
	if err != nil {
		log.Fatalf("Payload processing failed: %v", err)
	}

	log.Printf("Payload length: %d bytes", len(encryptedPayload))
	log.Println("First 16 bytes (hex):", hex.EncodeToString(encryptedPayload[:16]))

		if len(encryptedPayload) < 56 {
		log.Fatal("Payload too short - minimum 56 bytes required")
	}
	ephPub := encryptedPayload[:32]
	nonce := encryptedPayload[32:56]
	ciphertext := encryptedPayload[56:]

	log.Println("Extracted components:")
	log.Println("Ephemeral public key (hex):", hex.EncodeToString(ephPub))
	log.Println("Nonce (hex):", hex.EncodeToString(nonce))
	log.Printf("Ciphertext length: %d bytes", len(ciphertext))

	for i, pubKey := range pubKeys {
		log.Printf("\nProcessing key #%d", i+1)
		log.Println("Public key (hex):", hex.EncodeToString(pubKey))

		x25519Pub, err := convertEd25519ToX25519(pubKey)
		if err != nil {
			log.Printf("Key conversion failed: %v", err)
			continue
		}

		log.Println("Converted X25519 key (hex):", hex.EncodeToString(x25519Pub))

		_, err = curve25519.X25519(x25519Pub, ephPub)
		if err != nil {
			log.Println("X25519 operation failed:", err)
			continue
		}

		log.Println("Key processed successfully")
	}

	fmt.Println("\nProcessing completed")
}

func loadPublicKeys(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	log.Println("Raw PEM file content:")
	log.Println(string(data))

	var keys [][]byte
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		log.Printf("Found PEM block: Type=%s, Bytes=%d", block.Type, len(block.Bytes))
		if block.Type == "PUBLIC KEY" && len(block.Bytes) == ed25519.PublicKeySize {
			keys = append(keys, block.Bytes)
		}
		data = rest
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid Ed25519 PUBLIC KEY blocks found in %s", path)
	}

	log.Printf("Loaded %d valid public keys", len(keys))
	return keys, nil
}

func convertEd25519ToX25519(ed25519Pub []byte) ([]byte, error) {
	p, err := new(edwards25519.Point).SetBytes(ed25519Pub)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 point: %v", err)
	}
	return p.BytesMontgomery(), nil
}

func readPayload(input string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(input); err == nil {
		log.Println("Input decoded as base64")
		return decoded, nil
	}

	fileData, err := os.ReadFile(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload file: %v", err)
	}

	if decoded, err := base64.StdEncoding.DecodeString(string(fileData)); err == nil {
		log.Println("File content decoded as base64")
		return decoded, nil
	}

	log.Println("Treating input as raw data")
	return fileData, nil
}