package main

import (
	"fmt"
	"testing"

	aesgo "github.com/mario-areias/aes-go/aes-go"
	"github.com/mario-areias/aes-go/key"
)

func TestPaddingOracle(t *testing.T) {
	k := key.NewKey([16]byte([]byte("128bitsforkeysss")))

	oracle := Oracle{key: k}
	aes := aesgo.New(k)

	tests := []struct {
		name string

		input string
	}{
		{
			name:  "Simple decryption test",
			input: "Let's test if this is working!",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypted, err := aes.Encrypt(aesgo.CBC, []byte(test.input))
			if err != nil {
				t.Errorf("Error encrypting: %s", err)
			}

			decrypted := PaddingOracle(oracle, encrypted)
			decrypted, err = aesgo.RemovePadding(decrypted)
			if err != nil {
				t.Errorf("Error removing padding: %s", err)
			}
			if string(decrypted) != test.input {
				fmt.Printf("Got     : %s\n", string(decrypted))
				fmt.Printf("Expected: %s\n", test.input)
				t.Fail()
			}
		})
	}
}
