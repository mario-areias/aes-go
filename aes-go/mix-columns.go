package aesgo

// gmul performs Galois Field (256) multiplication of two bytes.
// implementation taking from wikipedia
func gmul(a, b byte) byte {
	var p byte = 0

	for counter := 0; counter < 8; counter++ {
		if (b & 1) != 0 {
			p ^= a
		}

		hiBitSet := (a & 0x80) != 0
		a <<= 1
		if hiBitSet {
			a ^= 0x1B // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}

	return p
}

// mixColumns mixes the columns of the state matrix.
func mixColumns(s [4][4]byte) [4][4]byte {
	// Temporary matrix to hold the results
	var ss [4][4]byte

	for c := 0; c < 4; c++ {
		ss[0][c] = gmul(0x02, s[0][c]) ^ gmul(0x03, s[1][c]) ^ s[2][c] ^ s[3][c]
		ss[1][c] = s[0][c] ^ gmul(0x02, s[1][c]) ^ gmul(0x03, s[2][c]) ^ s[3][c]
		ss[2][c] = s[0][c] ^ s[1][c] ^ gmul(0x02, s[2][c]) ^ gmul(0x03, s[3][c])
		ss[3][c] = gmul(0x03, s[0][c]) ^ s[1][c] ^ s[2][c] ^ gmul(0x02, s[3][c])
	}

	// Copy the results back to the original state matrix
	return ss
}
