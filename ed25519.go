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
	"bytes"
	"crypto"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"strconv"
	"unsafe"

	cryptorand "crypto/rand"

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
var sha512Pool = newObjPool[hash.Hash](8, 4, func() hash.Hash {
	return _Newi_()
},
)

//	var bytePools = [3]*objectPool[[]byte]{
//		newObjPool[[]byte](128, 6, func() []byte { return alignSlice(signatureSize, 32) }), // signaturePool //64
//		newObjPool[[]byte](128, 6, func() []byte { return alignSlice(publicKeyLen, 32) }),  // publicKeyPool //32
//		newObjPool[[]byte](128, 6, func() []byte { return alignSlice(privateKeyLen, 32) }), //privateKeyLen //64
//	}
func (p _PrivateKey) Public() _PublicKey {
	var publicKey = alignArray_32(32)
	// fmt.Println(len(publicKey))

	copy_AVX2_32(publicKey[:], p[32:])

	return publicKey[:]
}

func NewKeyFromSeed(seed []byte) _PrivateKey {
	_ = seed[31]

	// Outline the function body so that the returned key can be stack-allocated.
	var privateKey = alignArray_64(32)

	newKeyFromSeed(privateKey[:], seed)

	return privateKey[:]
}

func newKeyFromSeed(privateKey []byte, seed []byte) {
	_ = privateKey[63]
	_ = seed[31]
	if l := len(seed); l != seedLen {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	h := _sum512_(seed)
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	A := (&edwards25519.Point{}).ScalarBaseMult(s)
	// seed 32
	// privateKey 64

	//fmt.Println(len(A.Bytes())) // 32

	copy_AVX2_64(privateKey, seed)
	copy_AVX2_32(privateKey[32:], A.Bytes())
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
		signature := alignArray_64(32)
		// fmt.Println(len(signature))
		sign(signature[:], priv, message, domPrefixPh, context)
		// _ = signature[:0]

		return signature[:], nil
	case hash == crypto.Hash(0) && context != "": // Ed25519ctx
		if l := len(context); l > 255 {
			return nil, errors.New("ed25519: bad Ed25519ctx context length: " + strconv.Itoa(l))
		}
		var signature = alignArray_64(32)
		sign(signature[:], priv, message, domPrefixCtx, context)
		// bytePools[0].clear()

		return signature[:], nil
	case hash == crypto.Hash(0): // Ed25519
		return Sign(priv, message), nil
	default:
		return nil, errors.New("ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

func Sign(privateKey _PrivateKey, message []byte) []byte {
	_ = privateKey[63]

	// Outline the function body so that the returned signature can be
	// stack-allocated.
	var signature = alignSlice(signatureSize, 32)

	// fmt.Println(len(signature))
	sign(signature[:], privateKey, message, domPrefixPure, "")
	// _ = signature[:0]

	return signature[:]
}

func Verify__(publicKey _PublicKey, message, sig []byte) bool {
	return verify(publicKey, message, sig, domPrefixPure, "")
}

func verify(publicKey _PublicKey, message, sig []byte, domPrefix, context string) bool {
	_ = publicKey[31]
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

	kh := sha512Pool.get() // 1
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
	var h_Digest [64]byte

	hramDigest := kh.Sum(h_Digest[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	// [S]B = R + [k]A --> [k](-A) + [S]B = R
	minusA := (&edwards25519.Point{}).Negate(A)
	R := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, S)
	kh.Reset()
	sha512Pool.put(kh)

	return bytes.Equal(sig[:32], R.Bytes())
}

func sign(signature, privateKey, message []byte, domPrefix, context string) {
	_ = signature[63]
	_ = privateKey[63]

	if l := len(privateKey); l != privateKeyLen {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	seed, publicKey := privateKey[:seedLen], privateKey[seedLen:]

	h := _sum512_(seed)
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	prefix := h[32:]

	mh := sha512Pool.get() //2
	if domPrefix != domPrefixPure {
		mh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		mh.Write([]byte{byte(len(context))})
		mh.Write(lowlevelfunctions.StringToBytes(context))
	}
	mh.Write(prefix)
	mh.Write(message)
	var message_D, h_D [64]byte

	messageDigest := mh.Sum(message_D[:0])
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	mh.Reset()
	sha512Pool.put(mh)

	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	kh := sha512Pool.get() // 3
	if domPrefix != domPrefixPure {
		kh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		kh.Write([]byte{byte(len(context))})
		kh.Write(lowlevelfunctions.StringToBytes(context))
	}
	kh.Write(R.Bytes())
	kh.Write(publicKey)
	kh.Write(message)

	hramDigest := kh.Sum(h_D[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	kh.Reset()
	sha512Pool.put(kh)

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

	var seed = alignArray_32(32)
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed[:])
	// _ = seed[:0]

	publicKey := alignArray_32(32)

	copy_AVX2_32(publicKey[:], privateKey[32:])

	// _ = publicKey[:0]

	return publicKey[:], privateKey, nil
}

func b_32(s []byte) [32]byte {
	return *(*[32]byte)(unsafe.Pointer(&s))
}

func b_64(s []byte) [64]byte {

	return *(*[64]byte)(unsafe.Pointer(&s))
}
