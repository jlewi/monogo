package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// RandString generates a random string of the desired length
func RandString(length int) (string, error) {
	// RandBytes is base64 encoded so every 4 characters = 3 bytes
	numBytes := (float64(length) + 1.0) * .75
	b, err := RandBytes(int(numBytes))
	if err != nil {
		return "", err
	}

	return b[0:length], nil
}

// RandBytes generates a string with the given number of bytes.
// The string is base64 so the length is not the same as the number of bytes
func RandBytes(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
