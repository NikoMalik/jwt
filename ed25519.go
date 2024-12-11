package jwt

/*
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"strconv"
	"unsafe"

	cryptorand "crypto/rand"

	"bytes"

	"filippo.io/edwards25519"
	lowlevelfunctions "github.com/NikoMalik/low-level-functions"
)

// Domain separation prefixes used to disambiguate Ed25519/Ed25519ph/Ed25519ctx.
// See RFC 8032, Section 2 and Section 5.1.
const (
	INITIAL            = 1
	signatureFlagsMask = 224
	// domPrefixPure is empty for pure Ed25519.
	domPrefixPure = ""
	// domPrefixPh is dom2(phflag=1) for Ed25519ph. It must be followed by the
	// uint8-length prefixed context.
	domPrefixPh = "SigEd25519 no Ed25519 collisions\x01"
	// domPrefixCtx is dom2(phflag=0) for Ed25519ctx. It must be followed by the
	// uint8-length prefixed context.
	domPrefixCtx = "SigEd25519 no Ed25519 collisions\x00"
)

// / 1024,512,341,256,128

var sha512Pool *objPool[hash.Hash]

var digestPool *objPool[[]byte]

func (p _PrivateKey) Public() _PublicKey {
	// Acquire buffer from the pool

	publicKey := alignSliceWithArray_32(32)
	copy_AVX2_32(publicKey, p[32:])
	return publicKey
}

func NewKeyFromSeed(seed []byte) _PrivateKey {
	// Acquire and initialize buffer
	privateKey := alignSliceWithArray_64(32)
	newKeyFromSeed(privateKey, seed)

	return privateKey
}

func newKeyFromSeed(privateKey []byte, seed []byte) {

	if l := len(seed); l != seedLen {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}
	if l := len(privateKey); l != privateKeyLen {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := _sum512_(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	var hbytes = alignSliceWithArray_64(32)
	copy_AVX2_32(hbytes[:32], h[:32])

	s, err := edwards25519.NewScalar().SetUniformBytes(hbytes)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	A := new(edwards25519.Point).ScalarBaseMult(s)
	publicKey := A.Bytes()
	copy_AVX2_64(privateKey, seed)
	copy_AVX2_32(privateKey[32:], publicKey)

}

func (priv _PrivateKey) __Sign__(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := opts.HashFunc()
	context := ""
	if opts, ok := opts.(*_Options); ok {
		context = opts.Context
	}
	switch {
	case hash == crypto.SHA512: // Ed25519ph
		if l := len(message); l != sha512.Size {
			return nil, errors.New("ed25519: bad Ed25519ph message hash length: " + strconv.Itoa(l))
		}
		if l := len(context); l > 255 {
			return nil, errors.New("ed25519: bad Ed25519ph context length: " + strconv.Itoa(l))
		}
		signature := alignSliceWithArray_64(64)

		// fmt.Println(len(signature))
		sign(signature, priv, message, domPrefixPh, context)
		// _ = signature[:0]

		return signature, nil
	case hash == crypto.Hash(0) && context != "": // Ed25519ctx
		if l := len(context); l > 255 {
			return nil, errors.New("ed25519: bad Ed25519ctx context length: " + strconv.Itoa(l))
		}
		var s = alignSliceWithArray_64(64)
		sign(s, priv, message, domPrefixCtx, context)
		// bytePools[0].clear()

		return s, nil
	case hash == crypto.Hash(0): // Ed25519
		return Sign(priv, message), nil
	default:
		return nil, errors.New("ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

func Sign(privateKey _PrivateKey, message []byte) []byte {

	if len(privateKey) != privateKeyLen {
		panic("ed25519: bad private key length: " + strconv.Itoa(len(privateKey)))
	}

	// Outline the function body so that the returned signature can be
	// stack-allocated.
	var signature = make([]byte, signatureSize)

	sign(signature, privateKey, message, domPrefixPure, "")

	return signature
}

func Verify__(publicKey _PublicKey, message, sig []byte) bool {
	return verify(publicKey, message, sig, domPrefixPure, "")
}

func verify(publicKey _PublicKey, message, sig []byte, domPrefix, context string) bool {

	if l := len(publicKey); l != publicKeyLen {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != signatureSize || sig[63]&signatureFlagsMask != 0 {
		return false
	}

	A, err := (&edwards25519.Point{}).SetBytes(publicKey)
	if err != nil {
		return false
	}

	kh := sha512Pool.Get() // 1
	if kh == nil {
		panic("ed25519: internal error: getting hash failed")
	}
	if domPrefix != domPrefixPure {
		kh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		kh.Write([]byte{byte(len(context))})
		kh.Write(lowlevelfunctions.StringToBytes(context))
	}
	kh.Write(sig[:32])
	if sig[:32] == nil {
		panic("ed25519: internal error: getting hash failed")
	}
	kh.Write(publicKey)
	kh.Write(message)
	var hramDigest = digestPool.Get()

	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	// [S]B = R + [k]A --> [k](-A) + [S]B = R
	minusA := new(edwards25519.Point).Negate(A)
	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, minusA, S)
	kh.Reset()
	sha512Pool.Put(kh)
	hramDigest = hramDigest[:0]
	digestPool.Put(hramDigest)

	return bytes.Equal(sig[:32], R.Bytes())
}

func sign(signature, privateKey, message []byte, domPrefix, context string) {

	if l := len(privateKey); l != privateKeyLen {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	seed, publicKey := privateKey[:seedLen], privateKey[seedLen:]

	h := _sum512_(seed)
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	var hbytes = alignSliceWithArray_64(32)
	copy_AVX2_32(hbytes[:32], h[:32])
	s, err := edwards25519.NewScalar().SetUniformBytes(hbytes)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	prefix := h[32:]

	mh := sha512Pool.Get() //2
	if domPrefix != domPrefixPure {
		mh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		mh.Write([]byte{byte(len(context))})
		mh.Write(lowlevelfunctions.StringToBytes(context))
	}
	mh.Write(prefix)
	mh.Write(message)
	var messageDigest = digestPool.Get()

	messageDigest = mh.Sum(messageDigest)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	mh.Reset()
	sha512Pool.Put(mh)

	R := new(edwards25519.Point).ScalarBaseMult(r)

	kh := sha512Pool.Get() // 3
	if domPrefix != domPrefixPure {
		kh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		kh.Write([]byte{byte(len(context))})
		kh.Write(lowlevelfunctions.StringToBytes(context))
	}
	kh.Write(R.Bytes())
	kh.Write(publicKey)
	kh.Write(message)
	var hramDigest = digestPool.Get()

	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	kh.Reset()
	sha512Pool.Put(kh)
	messageDigest = messageDigest[:0]
	hramDigest = hramDigest[:0]
	digestPool.Put(messageDigest)
	digestPool.Put(hramDigest)

	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)

	copy_AVX2_32(signature[:32], R.Bytes())
	copy_AVX2_32(signature[32:], S.Bytes())
}

func __VerifyWithOptions__(publicKey _PublicKey, message, sig []byte, opts *_Options) error {
	switch {
	case opts.Hash == crypto.SHA512: // Ed25519ph
		if l := len(message); l != sha512.Size {
			return errors.New("ed25519: bad Ed25519ph message hash length: " + strconv.Itoa(l))
		}
		if l := len(opts.Context); l > 255 {
			return errors.New("ed25519: bad Ed25519ph context length: " + strconv.Itoa(l))
		}
		if !verify(publicKey, message, sig, domPrefixPh, opts.Context) {
			return errors.New("ed25519: invalid signature")
		}
		return nil
	case opts.Hash == crypto.Hash(0) && opts.Context != "": // Ed25519ctx
		if l := len(opts.Context); l > 255 {
			return errors.New("ed25519: bad Ed25519ctx context length: " + strconv.Itoa(l))
		}
		if !verify(publicKey, message, sig, domPrefixCtx, opts.Context) {
			return errors.New("ed25519: invalid signature")
		}
		return nil
	case opts.Hash == crypto.Hash(0): // Ed25519
		if !verify(publicKey, message, sig, domPrefixPure, "") {
			return errors.New("ed25519: invalid signature")
		}
		return nil
	default:
		return errors.New("ed25519: expected opts.Hash zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

type _Options struct {
	// for Ed25519ph. It can be at most 255 bytes in length.
	Hash crypto.Hash

	// Context, if not empty, selects Ed25519ctx or provides the context string
	// Hash can be zero for regular Ed25519, or crypto.SHA512 for Ed25519ph.
	Context string
}

func (o *_Options) HashFunc() crypto.Hash { return o.Hash }

func GenerateED25519(rand io.Reader) (_PublicKey, _PrivateKey, error) {
	return __generateKey__(rand)
}

func __generateKey__(rand io.Reader) (_PublicKey, _PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	var seed = [32]byte{}
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed[:])
	// _ = seed[:0]

	publicKey := alignSliceWithArray_32(32)

	copy_AVX2_32(publicKey, privateKey[32:])

	// _ = publicKey[:0]

	return publicKey, privateKey, nil
}

func b_32(s []byte) [32]byte {
	return *(*[32]byte)(unsafe.Pointer(&s))
}

func b_64(s []byte) *[64]byte {

	return (*[64]byte)(unsafe.Pointer(&s))
}
