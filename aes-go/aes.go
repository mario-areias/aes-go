package aesgo

import (
	"github.com/mario-areias/aes-go/key"
)

const (
	keyBlock = 4 // 4 bytes or 32 bits
)

func NewAES(key key.Key) AES {
	s := key.Len()
	switch s {
	case 128 / 8:
		return AES{key, 10, 0, nil}
	default:
		panic("Unsupported key size")
	}
}

type AES struct {
	key    key.Key
	rounds int

	currentRound    int
	currentRoundKey []byte
}

func (a *AES) generateNewRoundKey() {
	if a.currentRound == 0 {
		a.currentRoundKey = a.key.GetBytes()
		// fmt.Printf("Current round key: %02x\n", a.currentRoundKey)
		return
	}

	previousRoundKey := a.currentRoundKey

	w0 := previousRoundKey[0:4]
	w1 := previousRoundKey[4:8]
	w2 := previousRoundKey[8:12]
	w3 := previousRoundKey[12:16]

	t := rotWord([4]byte(w3))
	t = subWord([4]byte(t))
	t = rcon(a.currentRound-1, [4]byte(t))

	w4 := xor([4]byte(w0), [4]byte(t))
	w5 := xor([4]byte(w4), [4]byte(w1))
	w6 := xor([4]byte(w5), [4]byte(w2))
	w7 := xor([4]byte(w6), [4]byte(w3))

	roundKey := append(w4, append(w5, append(w6, w7...)...)...)

	a.currentRoundKey = roundKey
}

func (a *AES) nextRound() {
	a.currentRound++
}

func (a *AES) Encrypt(b []byte) []byte {
	l := len(b)
	blocks := l / 16

	result := make([]byte, blocks*16)

	for i := 0; i < blocks; i += 16 {
		block := convertArrayToMatrix([16]byte(b[i : i+16]))

		for j := 0; j <= a.rounds; j++ {
			a.generateNewRoundKey()
			block = a.encryptRound(block)
			a.nextRound()
		}

		r := convertMatrixToArray(block)
		result = append(result, r[:]...)
	}

	return result
}

func (a *AES) encryptRound(state [4][4]byte) [4][4]byte {
	key := convertArrayToMatrix([16]byte(a.currentRoundKey))
	// fmt.Printf("Key: %02x\n", key)

	if a.currentRound == 0 {
		r := addRoundKey(state, key)
		// fmt.Printf("Add round key rows: %02x\n", r)
		return r
	}

	if a.currentRound < a.rounds {
		r := subMatrix(state)
		// fmt.Printf("SubMatrix: %02x\n", r)

		r = shiftRows(r)
		// fmt.Printf("Shift Rows: %02x\n", r)

		r = mixColumns(r)
		// fmt.Printf("Mix columns Rows: %02x\n", r)

		r = addRoundKey(r, key)
		// fmt.Printf("Add round key rows: %02x\n", r)

		return r
	}

	r := subMatrix(state)
	// fmt.Printf("SubMatrix: %02x\n", r)

	r = shiftRows(r)
	// fmt.Printf("Shift Rows: %02x\n", r)

	r = addRoundKey(r, key)
	// fmt.Printf("Add round key rows: %02x\n", r)

	return r
}

func addRoundKey(state [4][4]byte, key [4][4]byte) [4][4]byte {
	return xorMatrix(state, key)
}

func subMatrix(word [4][4]byte) [4][4]byte {
	var s [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			s[i][j] = sBox()[word[i][j]]
		}
	}
	return s
}

func shiftRows(state [4][4]byte) [4][4]byte {
	var s [4][4]byte
	s[0] = state[0]

	s[1] = [4]byte{state[1][1], state[1][2], state[1][3], state[1][0]}
	s[2] = [4]byte{state[2][2], state[2][3], state[2][0], state[2][1]}
	s[3] = [4]byte{state[3][3], state[3][0], state[3][1], state[3][2]}

	return s
}

func convertArrayToMatrix(b [16]byte) [4][4]byte {
	var r [4][4]byte

	r[0] = [4]byte{b[0], b[4], b[8], b[12]}
	r[1] = [4]byte{b[1], b[5], b[9], b[13]}
	r[2] = [4]byte{b[2], b[6], b[10], b[14]}
	r[3] = [4]byte{b[3], b[7], b[11], b[15]}

	return r
}

func convertMatrixToArray(m [4][4]byte) [16]byte {
	var r [16]byte
	r[0] = m[0][0]
	r[1] = m[1][0]
	r[2] = m[2][0]
	r[3] = m[3][0]
	r[4] = m[0][1]
	r[5] = m[1][1]
	r[6] = m[2][1]
	r[7] = m[3][1]
	r[8] = m[0][2]
	r[9] = m[1][2]
	r[10] = m[2][2]
	r[11] = m[3][2]
	r[12] = m[0][3]
	r[13] = m[1][3]
	r[14] = m[2][3]
	r[15] = m[3][3]
	return r
}

func rotWord(word [4]byte) []byte {
	newWord := make([]byte, 4)
	newWord[0] = word[1]
	newWord[1] = word[2]
	newWord[2] = word[3]
	newWord[3] = word[0]

	return newWord
}

func subWord(word [4]byte) []byte {
	s := make([]byte, 4)
	for i := 0; i < 4; i++ {
		s[i] = sBox()[word[i]]
	}
	return s
}

func rcon(round int, word [4]byte) []byte {
	r := rconTable[round]
	return xor(word, r)
}

func xor(a, b [4]byte) []byte {
	x := make([]byte, 4)
	for i := 0; i < 4; i++ {
		x[i] = a[i] ^ b[i]
	}
	return x
}

func xorMatrix(a, b [4][4]byte) [4][4]byte {
	var x [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			x[i][j] = a[i][j] ^ b[i][j]
		}
	}
	return x
}

var rconTable = [10][4]byte{
	{0x01, 0x00, 0x00, 0x00},
	{0x02, 0x00, 0x00, 0x00},
	{0x04, 0x00, 0x00, 0x00},
	{0x08, 0x00, 0x00, 0x00},
	{0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00},
	{0x40, 0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00, 0x00},
	{0x1B, 0x00, 0x00, 0x00},
	{0x36, 0x00, 0x00, 0x00},
}
