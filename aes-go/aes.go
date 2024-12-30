package aesgo

import (
	"errors"

	"github.com/mario-areias/aes-go/key"
)

const (
	keyBlock = 4 // 4 bytes or 32 bits
)

func NewAES(key key.Key) AES {
	s := key.Len()
	switch s {
	case 128 / 8:
		return AES{key, 10, 0, make([][16]byte, 11)}
	default:
		panic("Unsupported key size")
	}
}

type AES struct {
	key    key.Key
	rounds int

	currentRound int
	roundKeys    [][16]byte
}

func (a *AES) generateAllKeys() {
	a.currentRound = 0

	for i := 0; i <= a.rounds; i++ {
		k := a.generateNewRoundKey()
		a.roundKeys[i] = k
		a.nextRound()
	}
}

func (a *AES) generateNewRoundKey() [16]byte {
	if a.currentRound == 0 {
		return [16]byte(a.key.GetBytes())
	}

	previousRoundKey := a.roundKeys[a.currentRound-1]

	w0 := previousRoundKey[0:4]
	w1 := previousRoundKey[4:8]
	w2 := previousRoundKey[8:12]
	w3 := previousRoundKey[12:16]

	t := rotWord([4]byte(w3))
	t = subWord([4]byte(t))
	t = rcon(a.currentRound, [4]byte(t))

	w4 := xor([4]byte(w0), [4]byte(t))
	w5 := xor([4]byte(w4), [4]byte(w1))
	w6 := xor([4]byte(w5), [4]byte(w2))
	w7 := xor([4]byte(w6), [4]byte(w3))

	roundKey := append(w4, append(w5, append(w6, w7...)...)...)

	return [16]byte(roundKey)
}

func (a *AES) nextRound() {
	a.currentRound++
}

func (a *AES) previousRound() {
	a.currentRound--
}

func (a *AES) EncryptECB(plainText []byte) []byte {
	blocks := createBlocks(plainText)

	r := make([]byte, 0)
	for _, block := range blocks {
		cipherBlock := a.EncryptBlock([16]byte(block))
		c := convertMatrixToArray(cipherBlock)
		s := c[:]
		r = append(r, s...)
	}

	return r
}

func (a *AES) EncryptCBC(plainText []byte, iv []byte) []byte {
	blocks := createBlocks(plainText)

	if len(iv) != 16 {
		panic("IV must have 16 bytes")
	}

	r := make([]byte, 0)
	previousCipherBlock := iv

	for _, block := range blocks {
		block = xorBytes(block, previousCipherBlock)
		cipherBlock := a.EncryptBlock([16]byte(block))

		c := convertMatrixToArray(cipherBlock)
		s := c[:]
		r = append(r, s...)

		previousCipherBlock = s
	}

	return r
}

func (a *AES) DecryptCBC(plainText []byte, iv []byte) ([]byte, error) {
	blocks := split(plainText)

	if len(iv) != 16 {
		panic("IV must have 16 bytes")
	}

	r := make([]byte, 0)
	previousCipherBlock := iv

	for _, block := range blocks {
		cipherBlock := a.DecryptBlock([16]byte(block))
		c := convertMatrixToArray(cipherBlock)
		s := c[:]

		s = xorBytes(s, previousCipherBlock)
		r = append(r, s...)

		previousCipherBlock = block
	}

	// ignoring error to make the code simpler
	b, err := removePadding(r)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func createBlocks(b []byte) [][]byte {
	blocks := split(b)
	last := blocks[len(blocks)-1]
	paddedLast := padding(last)

	if len(paddedLast) == 16 {
		blocks[len(blocks)-1] = paddedLast
	} else if len(paddedLast) == 32 {
		b := split(paddedLast)

		blocks[len(blocks)-1] = b[0]
		blocks = append(blocks, b[1])
	}

	return blocks
}

func (a *AES) DecryptECB(plainText []byte) []byte {
	blocks := split(plainText)

	r := make([]byte, 0)
	for _, block := range blocks {
		cipherBlock := a.DecryptBlock([16]byte(block))
		c := convertMatrixToArray(cipherBlock)
		s := c[:]
		r = append(r, s...)
	}

	// ignoring error to make the code simpler
	b, err := removePadding(r)
	if err != nil {
		panic(err)
	}

	return b
}

func removePadding(b []byte) ([]byte, error) {
	blocks := split(b)

	last := blocks[len(blocks)-1]
	p := b[len(b)-1]

	begin := len(last) - int(p)
	if begin < 0 {
		return nil, errors.New("Invalid padding")
	}

	for i := begin; i < len(last); i++ {
		if last[i] != p {
			return nil, errors.New("Invalid padding")
		}
	}

	last = last[:len(last)-int(p)]
	blocks[len(blocks)-1] = last

	return join(blocks), nil
}

func join(blocks [][]byte) []byte {
	var r []byte
	for _, block := range blocks {
		r = append(r, block...)
	}
	return r
}

func split(plainText []byte) [][]byte {
	n := 16
	l := len(plainText)
	var blocks [][]byte
	for i := 0; i < l; i += n {
		end := i + n
		if end > l {
			end = l
		}
		blocks = append(blocks, plainText[i:end])
	}
	return blocks
}

func padding(block []byte) []byte {
	n := 16
	l := len(block)

	if l == n {
		paddigBlock := []byte{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}
		block = append(block, paddigBlock...)
		return block
	}

	r := n - l
	s := make([]byte, 16)
	copy(s, block)

	for i := l; i < n; i++ {
		s[i] = byte(r)
	}

	return s
}

func (a *AES) EncryptBlock(b [16]byte) [4][4]byte {
	a.generateAllKeys()
	a.currentRound = 0

	block := convertArrayToMatrix(b)

	for j := 0; j <= a.rounds; j++ {
		block = a.encryptRound(block)
		a.nextRound()
	}

	return block
}

func (a *AES) DecryptBlock(b [16]byte) [4][4]byte {
	a.generateAllKeys()
	a.currentRound = a.rounds

	block := convertArrayToMatrix(b)

	for j := a.rounds; j >= 0; j-- {
		block = a.decryptRound(block)
		a.previousRound()
	}

	return block
}

func (a *AES) encryptRound(state [4][4]byte) [4][4]byte {
	key := convertArrayToMatrix(a.roundKeys[a.currentRound])

	if a.currentRound == 0 {
		r := addRoundKey(state, key)
		return r
	}

	r := subMatrix(state)
	r = shiftRows(r)

	if a.currentRound < a.rounds {
		// mix columns don't apply to the last round
		r = mixColumns(r)
	}

	r = addRoundKey(r, key)

	return r
}

func (a *AES) decryptRound(state [4][4]byte) [4][4]byte {
	key := convertArrayToMatrix(a.roundKeys[a.currentRound])

	if a.currentRound == a.rounds {
		r := addRoundKey(state, key)
		return r
	}

	r := invShiftRows(state)
	r = invSubMatrix(r)
	r = addRoundKey(r, key)

	if a.currentRound > 0 {
		// invmix columns don't apply to the last round
		r = invMixColumns(r)
	}

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

func invSubMatrix(word [4][4]byte) [4][4]byte {
	var s [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			s[i][j] = invSBox()[word[i][j]]
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

func invShiftRows(state [4][4]byte) [4][4]byte {
	var s [4][4]byte
	s[0] = state[0]

	s[1] = [4]byte{state[1][3], state[1][0], state[1][1], state[1][2]}
	s[2] = [4]byte{state[2][2], state[2][3], state[2][0], state[2][1]}
	s[3] = [4]byte{state[3][1], state[3][2], state[3][3], state[3][0]}

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
	r := rconTable[round-1] // this is to avoid overflows
	return xor(word, r)
}

func xor(a, b [4]byte) []byte {
	x := make([]byte, 4)
	for i := 0; i < 4; i++ {
		x[i] = a[i] ^ b[i]
	}
	return x
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("Different lengths")
	}

	x := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
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
