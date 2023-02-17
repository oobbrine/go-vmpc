// Package vmpc implements VMPC stream cipher by Bartosz Żółtak.
// VMPC is a modification of the RC4 cipher.
//
// Warning: VMPC is a legacy cipher and therefore it's not
// recommended for protection of highly classified data.
package vmpc

// For more information on the VMPC stream cipher, see [VMPC] 9.
//
// [VMPC]: http://www.vmpcfunction.com/vmpc.pdf

import (
	"errors"
	"strconv"
)

// A Cipher represents an instance of VMPC encryption using
// a particular key and iv pair.
type Cipher struct {
	p [256]byte
	s byte
}

// NewCipher creates and returns a Cipher.
// Both key and iv should be between 16 and 64 bytes long.
func NewCipher(key, iv []byte) (*Cipher, error) {
	keylen := len(key)
	if keylen < 16 || keylen > 64 {
		return nil, errors.New("crypto/vmpc: invalid key size " + strconv.Itoa(keylen))
	}
	ivlen := len(iv)
	if ivlen < 16 || ivlen > 64 {
		return nil, errors.New("crypto/vmpc: invalid iv size " + strconv.Itoa(ivlen))
	}
	c := new(Cipher)
	for i, _ := range c.p {
		c.p[i] = byte(i)
	}
	c.ksaRound(key, keylen)
	c.ksaRound(iv, ivlen)

	return c, nil
}

// Encrypt encrypts an array of arbitrary size from src to dst.
func (c *Cipher) Encrypt(dst, src []byte) {
	// Create local copies of struct fields
	// in order to avoid overwriting.
	s := c.s
	p := c.p
	j := 0
	for i, _ := range src {
		s = p[s+p[j]]
		dst[i] = src[i] ^ p[p[p[s]]+1]
		p[j], p[s] = p[s], p[j]
		j = (j + 1) % 256
	}
}

// Decrypt decrypts an array of arbitrary size from src to dst.
func (c *Cipher) Decrypt(dst, src []byte) {
	c.Encrypt(dst, src)
}

// ksaRound performs one round of VMPC-KSA as defined in [VMPC] 10.
func (c *Cipher) ksaRound(ma []byte, mb int) {
	for i := 0; i < 768; i++ {
		mod := i % 256
		c.s = c.p[c.s+c.p[mod]+ma[i%mb]]
		c.p[mod], c.p[c.s] = c.p[c.s], c.p[mod]
	}
}
