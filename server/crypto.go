package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

// AES block size
const BlockSize = aes.BlockSize

// Pad function to make data a multiple of the AES block size
func pad(data []byte) []byte {
	padding := BlockSize - len(data)%BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Unpad function to remove padding after decryption
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("unpad error, incorrect padding")
	}
	return data[:(length - unpadding)], nil
}

// EncryptData encrypts the given data using AES with the provided key and IV (initialization vector)
func EncryptData(data, key, iv string) (string, error) {
	keyBytes := []byte(key)
	ivBytes := []byte(iv)
	plainText := []byte(data)

	// Create AES cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Ensure the IV is the correct length (16 bytes for AES)
	if len(ivBytes) != BlockSize {
		return "", fmt.Errorf("IV length must be %d bytes", BlockSize)
	}

	// Pad the plaintext to a multiple of the block size
	paddedData := pad(plainText)

	// Create a CBC encrypter
	mode := cipher.NewCBCEncrypter(block, ivBytes)

	// Encrypt the padded data
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)

	// Base64 encode the encrypted data
	encryptedBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	return encryptedBase64, nil
}

// DecryptData decrypts the Base64 encoded encrypted string using AES with the given key and IV
func DecryptData(encryptedBase64, key, iv string) (string, error) {
	keyBytes := []byte(key)
	ivBytes := []byte(iv)

	// Decode the Base64 encoded string
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", err
	}

	// Create AES cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Ensure the IV is the correct length (16 bytes for AES)
	if len(ivBytes) != BlockSize {
		return "", fmt.Errorf("IV length must be %d bytes", BlockSize)
	}

	// Create a CBC decrypter
	mode := cipher.NewCBCDecrypter(block, ivBytes)

	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding from the decrypted data
	unpaddedData, err := unpad(plaintext)
	if err != nil {
		return "", err
	}

	// Return the decrypted data as a string
	return string(unpaddedData), nil
}
