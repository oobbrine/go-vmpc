// (The MIT License)
//
// Copyright (c) 2023 Osteotomist (osteotomist@proton.me)
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package vmpc

// All tests used in this file are extracted from [VMPC] 11.
//
// [VMPC]: http://www.vmpcfunction.com/vmpc.pdf

import (
	"bytes"
	"testing"
)

const maxOfs = 102400

var testKey = []byte{
	0x96, 0x61, 0x41, 0x0a, 0xb7, 0x97, 0xd8, 0xa9,
	0xeb, 0x76, 0x7c, 0x21, 0x17, 0x2d, 0xf6, 0xc7,
}

var testVec = []byte{
	0x4b, 0x5c, 0x2f, 0x00, 0x3e, 0x67, 0xf3, 0x95,
	0x57, 0xa8, 0xd2, 0x6f, 0x3d, 0xa2, 0xb1, 0x55,
}

var testOutput = []struct {
	out []byte
	ofs int
}{
	{
		[]byte{0xa8, 0x24, 0x79, 0xf5},
		0,
	},
	{
		[]byte{0xb8, 0xfc, 0x66, 0xa4},
		252,
	},
	{
		[]byte{0xe0, 0x56, 0x40, 0xa5},
		1020,
	},
	{
		[]byte{0x81, 0xca, 0x49, 0x9a},
		102396,
	},
}

func TestCipher(t *testing.T) {
	c, err := NewCipher(testKey, testVec)
	if err != nil {
		t.Errorf("NewCipher: %v", err)
		return
	}
	dst := make([]byte, maxOfs)
	src := make([]byte, maxOfs)

	// Test Encrypt.
	c.Encrypt(dst, src)
	for i, v := range testOutput {
		out := v.out
		ofs := v.ofs

		outlen := len(out)
		tmp := make([]byte, outlen)
		copy(tmp, dst[ofs:ofs+outlen])

		if !bytes.Equal(tmp, out) {
			t.Errorf("#%d: encrypt = %x want %x", i, tmp, out)
			return
		}
	}
	
	// Test Decrypt.
	tmp := make([]byte, maxOfs)
	c.Decrypt(src, dst)
	if !bytes.Equal(src, tmp) {
		t.Errorf("decrypt = %x want %x", src, tmp)
		return
	}
}
