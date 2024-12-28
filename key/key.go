package key

import (
	"crypto/rand"
)

type Key interface {
	GetBytes() []byte
	Len() int
}

type key128 struct {
	material [16]byte
}

func (k *key128) GetBytes() []byte {
	return k.material[:]
}

func (k *key128) Len() int {
	return len(k.material)
}

func Bit128() Key {
	b := generateRandomBytes(16)
	return &key128{material: [16]byte(b)}
}

func NewKey(material [16]byte) Key {
	return &key128{material: material}
}

func generateRandomBytes(n int) []byte {
	randBytes := make([]byte, n)

	i, err := rand.Read(randBytes)
	if i != n || err != nil {
		panic("Could not generate random bytes")
	}

	return randBytes
}
