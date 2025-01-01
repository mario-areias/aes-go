package main

import (
	aesgo "github.com/mario-areias/aes-go/aes-go"
	"github.com/mario-areias/aes-go/key"
)

// An oracle can be thought as a server the decrypt the output but doesn't return the plain text to its caller.
// For example, a web server that decrypts a cookie to check for user permissions.
// For that reason the Oracle has a decrypt method that only returns an error to the caller.
type Oracle struct {
	key key.Key
}

func (o *Oracle) Decrypt(encrypted []byte) error {
	aes := aesgo.New(o.key)
	// ignoring decrypted output because the caller shouldn't have access to it
	_, err := aes.Decrypt(aesgo.CBC, encrypted)
	return err
}

func PaddingOracle(oracle Oracle, encrypted []byte) []byte {
	// encrypted is the IV + the cyphertext. So the last first block is always the IV
	decrypted := make([]byte, len(encrypted))
	dec := make([]byte, 16)

	blocks := split(encrypted)

	for i := len(blocks) - 1; i >= 1; i-- {
		last := blocks[i]
		prev := blocks[i-1]

		dec = make([]byte, 16)

		// copy previous to avoid modifying the original
		p := make([]byte, 16)
		copy(p, prev)

		for z := 15; z >= 0; z-- {
			// b is the byte that when xoring with the decrypted byte returns a valid padding byte.
			// For example, if the last padding byte is 0x2e it means 0x2e ^ ? = 0x01.
			// To find the actual decrypted byte then we do 0x2e ^ 0x01 = ?. Which in this case is 0x2f
			b := findPaddingByte(oracle, p, last, dec, z)

			// x is the decrypted byte. It is the result of the xor between the byte found and the padding value.
			// reason here: https://www.nccgroup.com/au/research-blog/cryptopals-exploiting-cbc-padding-oracles/
			x := byte(b) ^ byte(16-z)

			// dec is used to store the decrypted bytes.
			// It is used to change the value from the previous block to get the previous valid bytes.
			// For example, if dec[15] = 0x2f then when trying to find the byte number 14, we need to adjust the adjust the byte 15
			// to also provide the correct padding value.
			//
			// To find the padding byte for the 15th byte the algorithm tried all bytes until it found 0x2e. Which is 0x2f ^ 0x01
			// dec[15] = 0x2f ^ 0x01 = 0x2e
			//
			// To find the padding byte for the 14th byte the 15th should adjust its value.
			// dec[15] = 0x2f ^ 0x02 = 0x2d
			// dec[14] =  ?   ^ 0x02 = <algorithm will try all values until it finds the correct byte>
			//
			// And so on until the first byte.
			// dec[15] = 0x2f ^ 0x03 = 0x2c
			// dec[14] = 0x15 ^ 0x03 = 0x16  // assuming the previous step found the byte 0x15 to be the correct value for the 14th byte
			// dec[13] = ? ^    0x03 = <algorithm will try all values until it finds the correct byte>
			dec[z] = x

			// the final step to decrypt in CBC is to XOR against the previous cyphertext.
			// So we do that here to store the actual plain text byte
			decrypted[i*16+z] = x ^ prev[z]
		}

	}

	return decrypted[16:] // remove IV from decryption block
}

// This function finds the padding byte by trying all possible values.
func findPaddingByte(oracle Oracle, prev, last, dec []byte, z int) byte {
	paddingValue := byte(16 - z)

	if paddingValue > 0x1 {
		for x := 15; x > z; x-- {
			y := dec[x] ^ paddingValue
			prev[x] = y
		}
	}

	for j := 0x0; j <= 0xff; j++ {
		prev[z] = byte(j)
		err := oracle.Decrypt(append(prev, last...))
		if err == nil {
			if z == 15 {
				prev[14] ^= byte(1)
				err := oracle.Decrypt(append(prev, last...))
				if err != nil {
					continue
				}
			}

			return byte(j)
		}
	}

	panic("Could not find padding byte")
}

func split(b []byte) [][]byte {
	n := 16
	l := len(b)
	var blocks [][]byte
	for i := 0; i < l; i += n {
		end := i + n
		if end > l {
			end = l
		}
		blocks = append(blocks, b[i:end])
	}
	return blocks
}
