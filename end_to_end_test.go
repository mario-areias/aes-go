package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"

	aesgo "github.com/mario-areias/aes-go/aes-go"
	"github.com/mario-areias/aes-go/key"
)

func TestCBCStd(t *testing.T) {
	k := key.Bit128()

	aes := aesgo.New(k)

	plaintext := []byte("Let's test if this is working!")

	// encrypt with our implementation and decrypt with std
	cipher, err := aes.Encrypt(aesgo.CBC, plaintext)
	if err != nil {
		t.Errorf("Error encrypting: %s", err)
	}

	decrypted, err := stdCBCDecrypt(cipher[16:], k.GetBytes(), cipher[:16])
	if err != nil {
		t.Errorf("Error decrypting: %s", err)
	}

	if plaintextStr := string(plaintext); plaintextStr != string(decrypted) {
		t.Errorf("Decrypted text does not match plaintext. Got: %s, Expected: %s", decrypted, plaintextStr)
	}

	// encrypt with std and decrypt with our implementation
	iv := key.Bit128().GetBytes()
	encrypted, err := stdCBCEncrypt(plaintext, k.GetBytes(), iv)
	if err != nil {
		t.Errorf("Error encrypting: %s", err)
	}

	decrypted, err = aes.Decrypt(aesgo.CBC, encrypted)
	if err != nil {
		t.Errorf("Error decrypting: %s", err)
	}

	if plaintextStr := string(plaintext); plaintextStr != string(decrypted) {
		t.Errorf("Decrypted text does not match plaintext. Got: %s, Expected: %s", decrypted, plaintextStr)
	}
}

func TestCTRStd(t *testing.T) {
	k := key.Bit128()

	aes := aesgo.New(k)

	plaintext := []byte("Let's test if this is working!")

	// encrypt with our implementation and decrypt with std
	cipher, err := aes.Encrypt(aesgo.CTR, plaintext)
	if err != nil {
		t.Errorf("Error encrypting: %s", err)
	}

	decrypted, err := stdCTRDecrypt(cipher[16:], k.GetBytes(), cipher[:16])
	if err != nil {
		t.Errorf("Error decrypting: %s", err)
	}

	if plaintextStr := string(plaintext); plaintextStr != string(decrypted) {
		t.Errorf("Decrypted text does not match plaintext. Got: %s, Expected: %s", decrypted, plaintextStr)
	}
}

func TestPaddingOracleAttackWithStdEncryption(t *testing.T) {
	k := key.Bit128()
	iv := key.Bit128().GetBytes()

	plaintext := []byte("Let's test if this attack works!!")

	o := Oracle{key: k}

	stdEncrypted, err := stdCBCEncrypt(plaintext, k.GetBytes(), iv)
	if err != nil {
		t.Errorf("Error encrypting: %s", err)
	}

	decrypted := PaddingOracle(o, stdEncrypted)

	unpadded, err := aesgo.RemovePadding(decrypted)
	if err != nil {
		t.Errorf("Error removing padding: %s", err)
	}

	if plaintextStr := string(plaintext); plaintextStr != string(unpadded) {
		t.Errorf("Decrypted text does not match plaintext. Got: %s, Expected: %s", unpadded, plaintextStr)
	}
}

// Function to stdCBCEncrypt plaintext using AES in CBC mode
func stdCBCEncrypt(plainText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad the plaintext to be a multiple of the block size
	plainText = pad(plainText, aes.BlockSize)

	// Create a new CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the plaintext
	cipherText := make([]byte, len(plainText))
	mode.CryptBlocks(cipherText, plainText)

	// Prepend the IV to the ciphertext for use in decryption
	return append(iv, cipherText...), nil
}

// Function to stdCBCDecrypt ciphertext using AES in CBC mode
func stdCBCDecrypt(cipherText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the ciphertext
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)

	// Unpad the plaintext
	return unpad(plainText)
}

func stdCTRDecrypt(cipherText, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new CTR decrypter
	mode := cipher.NewCTR(block, nonce)

	// Decrypt the ciphertext
	plainText := make([]byte, len(cipherText))
	mode.XORKeyStream(plainText, cipherText)

	return plainText, nil
}

func pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return src[:(length - unpadding)], nil
}
