package aesgo

import (
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	"github.com/mario-areias/aes-go/key"
)

func TestEncryptBlock(t *testing.T) {
	// This test is extracted from the FIPS 197 document
	// https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
	// Appendix B - Cipher Example
	// Appendix C.1 AES-128 Encryption

	tests := []struct {
		name       string
		encryption bool

		input    [16]byte
		material [16]byte

		expected [4][4]byte
	}{
		{
			name: "Appendix B. Encryption",

			encryption: true,

			input:    [16]byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34},
			material: [16]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},

			expected: [4][4]byte{
				{0x39, 0x02, 0xdc, 0x19},
				{0x25, 0xdc, 0x11, 0x6a},
				{0x84, 0x09, 0x85, 0x0b},
				{0x1d, 0xfb, 0x97, 0x32},
			},
		},
		{
			name: "Appendix B. Decryption",

			encryption: false,

			input:    [16]byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32},
			material: [16]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},

			expected: [4][4]byte{
				{0x32, 0x88, 0x31, 0xe0},
				{0x43, 0x5a, 0x31, 0x37},
				{0xf6, 0x30, 0x98, 0x07},
				{0xa8, 0x8d, 0xa2, 0x34},
			},
		},
		{

			name: "Appendix C.1. Encryption",

			encryption: true,

			input:    [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			material: [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},

			// 69c4e0d8 6a7b0430 d8cdb780 70b4c55a
			expected: [4][4]byte{
				{0x69, 0x6a, 0xd8, 0x70},
				{0xc4, 0x7b, 0xcd, 0xb4},
				{0xe0, 0x04, 0xb7, 0xc5},
				{0xd8, 0x30, 0x80, 0x5a},
			},
		},
		{

			name: "Appendix C.1. Decryption",

			encryption: false,

			input:    [16]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
			material: [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},

			expected: [4][4]byte{
				{0x00, 0x44, 0x88, 0xcc},
				{0x11, 0x55, 0x99, 0xdd},
				{0x22, 0x66, 0xaa, 0xee},
				{0x33, 0x77, 0xbb, 0xff},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := key.NewKey(test.material)
			aes := New(key)

			var output [4][4]byte

			if test.encryption {
				output = aes.EncryptBlock(test.input)
			} else {
				output = aes.DecryptBlock(test.input)
			}

			if output != test.expected {
				a := convertMatrixToArray(output)
				fmt.Printf("Got: %02x\n", a)
				fmt.Printf("Got: %02x\n", output)
				fmt.Printf("Expected: %02x\n", test.expected)

				t.Fail()
			}
		})
	}
}

func TestPadding(t *testing.T) {
	tests := []struct {
		name  string
		block []byte

		expected []byte
	}{
		{
			name: "block with 16 bytes",

			block:    []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34},
			expected: []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10},
		},
		{
			name: "block with 4 bytes",

			block:    []byte{0x32, 0x43, 0xf6, 0xa8},
			expected: []byte{0x32, 0x43, 0xf6, 0xa8, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := padding(test.block)
			if !slices.Equal(output, test.expected) {
				fmt.Printf("Got     : %02x\n", output)
				fmt.Printf("Expected: %02x\n", test.expected)
				t.Fail()
			}
		})
	}
}

func TestRemovePadding(t *testing.T) {
	tests := []struct {
		name  string
		block []byte

		expected []byte

		error bool
	}{
		{
			name: "simple test with 0x1 padding",

			block:    []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x01},
			expected: []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07},
		},
		{
			name: "simple test with last byte as 0x0",

			block: []byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x0},

			error: true,
		},
		{
			name: "invalid padding",

			block: []byte{0x32, 0x43, 0xf6, 0x06},

			error: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output, err := RemovePadding(test.block)

			switch {
			case test.error && err == nil:
				t.Errorf("Expected error, got nil")
				t.FailNow()
			case !test.error && err != nil:
				t.Errorf("Expected nil, got %v", err)
				t.FailNow()
			}

			if !slices.Equal(output, test.expected) {
				fmt.Printf("Got     : %02x\n", output)
				fmt.Printf("Expected: %02x\n", test.expected)
				t.Fail()
			}
		})
	}
}

func TestEncryptionECB(t *testing.T) {
	tests := []struct {
		name string

		encryption bool

		input string
		key   string

		expected string
	}{
		{
			name: "Simple encryption test",

			encryption: true,

			input:    "Let's test if this is working!",
			key:      "128bitsforkeysss",
			expected: "a922ddf330c834f6b705ff9c762841ecd6201d058f9b8c9186d6dd7624d3cd20",
		},
		{
			name: "Simple decryption test",

			encryption: false,

			input:    "a922ddf330c834f6b705ff9c762841ecd6201d058f9b8c9186d6dd7624d3cd20",
			key:      "128bitsforkeysss",
			expected: "Let's test if this is working!",
		},
		{
			name: "Example encryption with exactly 3 blocks of 16 bytes",

			encryption: true,

			input:    "The quick brown fox jumps over the lazy dog 1234",
			key:      "128bitsforkeysss",
			expected: "e6a120617fd61acd2f674683e668faf80de7195d49c076d0b6e4c6112a90095c7693de53e643d4c013c897d0f6cee6f8966128de2bef1fe7b381b11d7b38bf1f",
		},
		{
			name: "Example decryption with exactly 3 blocks of 16 bytes",

			encryption: false,

			input:    "e6a120617fd61acd2f674683e668faf80de7195d49c076d0b6e4c6112a90095c7693de53e643d4c013c897d0f6cee6f8966128de2bef1fe7b381b11d7b38bf1f",
			key:      "128bitsforkeysss",
			expected: "The quick brown fox jumps over the lazy dog 1234",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := key.NewKey([16]byte([]byte(test.key)))
			aes := New(key)

			var output []byte
			var result string

			if test.encryption {
				output = aes.encryptECB([]byte(test.input))
				result = hex.EncodeToString(output)
			} else {
				b := make([]byte, len(test.input)/2)
				hex.Decode(b, []byte(test.input))
				output = aes.decryptECB(b)
				result = string(output)
			}

			if result != test.expected {
				fmt.Printf("Got     : %s\n", result)
				fmt.Printf("Expected: %s\n", test.expected)
				t.Fail()
			}
		})
	}
}

func TestEncryptionCBC(t *testing.T) {
	tests := []struct {
		name string

		encryption bool
		error      bool

		input string
		key   string
		iv    string

		expected string
	}{
		{
			name: "Simple encryption test",

			encryption: true,

			input:    "Let's test if this is working!",
			key:      "128bitsforkeysss",
			iv:       "9876543210abcdef",
			expected: "3938373635343332313061626364656663163f78c264d799786c665a3858ef2020401081059a51efcb02e3585002f90f",
		},
		{
			name: "Simple decryption test",

			encryption: false,

			input:    "3938373635343332313061626364656663163f78c264d799786c665a3858ef2020401081059a51efcb02e3585002f90f",
			key:      "128bitsforkeysss",
			expected: "Let's test if this is working!",
		},
		{
			name: "Padding error",

			encryption: false,
			error:      true,

			// changed last bit from 0f to 0e to make the padding invalid
			input: "3938373635343332313061626364656663163f78c264d799786c665a3858ef2020401081059a51efcb02e3585002f90e",
			key:   "128bitsforkeysss",
			iv:    "9876543210abcdef",
		},
		{
			name: "Example encryption with exactly 3 blocks of 16 bytes",

			encryption: true,

			input:    "The quick brown fox jumps over the lazy dog 1234",
			key:      "128bitsforkeysss",
			iv:       "9876543210abcdef",
			expected: "39383736353433323130616263646566335a1adbd467c9182720ab33360ee5e201255e782f3fa328a390f8d74f1705f67267ae74c5c6c34793a421909c66609d88dfc28eb5f6b8de63bff5662fe3af2d",
		},
		{
			name: "Example decryption with exactly 3 blocks of 16 bytes",

			encryption: false,

			input:    "39383736353433323130616263646566335a1adbd467c9182720ab33360ee5e201255e782f3fa328a390f8d74f1705f67267ae74c5c6c34793a421909c66609d88dfc28eb5f6b8de63bff5662fe3af2d",
			key:      "128bitsforkeysss",
			expected: "The quick brown fox jumps over the lazy dog 1234",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := key.NewKey([16]byte([]byte(test.key)))
			aes := New(key)

			var output []byte
			var result string

			if test.encryption {
				output = aes.encryptCBC([]byte(test.input), []byte(test.iv))
				result = hex.EncodeToString(output)
			} else {
				b := make([]byte, len(test.input)/2)
				hex.Decode(b, []byte(test.input))

				iv := b[:16]
				input := b[16:]

				output, err := aes.decryptCBC(input, iv)

				switch {
				case test.error && err == nil:
					t.Errorf("Expected error, got nil")
					t.FailNow()
				case !test.error && err != nil:
					t.Errorf("Expected nil, got %v", err)
					t.FailNow()
				}

				result = string(output)
			}

			if result != test.expected {
				fmt.Printf("Got     : %s\n", result)
				fmt.Printf("Expected: %s\n", test.expected)
				t.Fail()
			}
		})
	}
}
