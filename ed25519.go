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
var sha512Pool = newObjPool[hash.Hash](128, 6, func() hash.Hash {
	return _Newi_()
},
)

var bytePools = [3]*objectPool[[]byte]{
	newObjPool[[]byte](128, 6, func() []byte { return lowlevelfunctions.MakeNoZero(signatureSize) }), // signaturePool //0
	newObjPool[[]byte](128, 6, func() []byte { return lowlevelfunctions.MakeNoZero(publicKeyLen) }),  // publicKeyPool //1
	newObjPool[[]byte](128, 6, func() []byte { return lowlevelfunctions.MakeNoZero(privateKeyLen) }), //privateKeyLen //2
}

func (p _PrivateKey) Public() _PublicKey {
	var publicKey = bytePools[1].get()
	// fmt.Println(len(publicKey))
	_copy_(publicKey, p[32:])

	bytePools[1].put(publicKey)

	return publicKey
}

func NewKeyFromSeed(seed []byte) _PrivateKey {

	// Outline the function body so that the returned key can be stack-allocated.
	var privateKey = bytePools[2].get()

	newKeyFromSeed(privateKey, seed)
	bytePools[2].put(privateKey)
	return privateKey
}

func newKeyFromSeed(privateKey []byte, seed []byte) {
	if l := len(seed); l != seedLen {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	h := _sum512_(seed)
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	A := (&edwards25519.Point{}).ScalarBaseMult(s)

	_copy_(privateKey, seed)
	_copy_(privateKey[32:], A.Bytes())
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
		signature := bytePools[0].get()
		// fmt.Println(len(signature))
		sign(signature, priv, message, domPrefixPh, context)
		// _ = signature[:0]

		bytePools[0].put(signature)
		return signature, nil
	case hash == crypto.Hash(0) && context != "": // Ed25519ctx
		if l := len(context); l > 255 {
			return nil, errors.New("ed25519: bad Ed25519ctx context length: " + strconv.Itoa(l))
		}
		var signature = bytePools[0].get()

		sign(signature, priv, message, domPrefixCtx, context)

		bytePools[0].put(signature)
		return signature, nil
	case hash == crypto.Hash(0): // Ed25519
		return Sign(priv, message), nil
	default:
		return nil, errors.New("ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

func Sign(privateKey _PrivateKey, message []byte) []byte {
	// Outline the function body so that the returned signature can be
	// stack-allocated.
	var signature = bytePools[0].get()
	// fmt.Println(len(signature))
	sign(signature, privateKey, message, domPrefixPure, "")
	// _ = signature[:0]
	bytePools[0].put(signature)
	return signature
}

func __Verify__(publicKey _PublicKey, message, sig []byte) bool {
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
	// RBytes := R.Bytes()
	// SBytes := S.Bytes()
	// signature[0] = RBytes[0]
	// signature[1] = RBytes[1]
	// signature[2] = RBytes[2]
	// signature[3] = RBytes[3]
	// signature[4] = RBytes[4]
	// signature[5] = RBytes[5]
	// signature[6] = RBytes[6]
	// signature[7] = RBytes[7]
	// signature[8] = RBytes[8]
	// signature[9] = RBytes[9]
	// signature[10] = RBytes[10]
	// signature[11] = RBytes[11]
	// signature[12] = RBytes[12]
	// signature[13] = RBytes[13]
	// signature[14] = RBytes[14]
	// signature[15] = RBytes[15]
	// signature[16] = RBytes[16]
	// signature[17] = RBytes[17]
	// signature[18] = RBytes[18]
	// signature[19] = RBytes[19]
	// signature[20] = RBytes[20]
	// signature[21] = RBytes[21]
	// signature[22] = RBytes[22]
	// signature[23] = RBytes[23]
	// signature[24] = RBytes[24]
	// signature[25] = RBytes[25]
	// signature[26] = RBytes[26]
	// signature[27] = RBytes[27]
	// signature[28] = RBytes[28]
	// signature[29] = RBytes[29]
	// signature[30] = RBytes[30]
	// signature[31] = RBytes[31]
	// signature[32] = SBytes[0]
	// signature[33] = SBytes[1]
	// signature[34] = SBytes[2]
	// signature[35] = SBytes[3]
	// signature[36] = SBytes[4]
	// signature[37] = SBytes[5]
	// signature[38] = SBytes[6]
	// signature[39] = SBytes[7]
	// signature[40] = SBytes[8]
	// signature[41] = SBytes[9]
	// signature[42] = SBytes[10]
	// signature[43] = SBytes[11]
	// signature[44] = SBytes[12]
	// signature[45] = SBytes[13]
	// signature[46] = SBytes[14]
	// signature[47] = SBytes[15]
	// signature[48] = SBytes[16]
	// signature[49] = SBytes[17]
	// signature[50] = SBytes[18]
	// signature[51] = SBytes[19]
	// signature[52] = SBytes[20]
	// signature[53] = SBytes[21]
	// signature[54] = SBytes[22]
	// signature[55] = SBytes[23]
	// signature[56] = SBytes[24]
	// signature[57] = SBytes[25]
	// signature[58] = SBytes[26]
	// signature[59] = SBytes[27]
	// signature[60] = SBytes[28]
	// signature[61] = SBytes[29]
	// signature[62] = SBytes[30]
	// signature[63] = SBytes[31]
	//
	_copy_(signature[:32], R.Bytes())
	_copy_(signature[32:], S.Bytes())
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

func __generateKey__(rand io.Reader) (_PublicKey, _PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	var seed = bytePools[1].get()
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed[:])
	// _ = seed[:0]

	bytePools[1].put(seed)
	publicKey := bytePools[1].get()
	_copy_(publicKey[:], privateKey[32:])

	// _ = publicKey[:0]
	bytePools[1].put(publicKey)

	return publicKey, privateKey, nil
}

func b_32(s []byte) *[32]byte {
	if len(s) < 32 {
		panic("b_32 must be 32 slice")
	}

	return (*[32]byte)(unsafe.Pointer(&s))
}

func b_64(s []byte) *[64]byte {
	if len(s) < 64 {
		panic("b_64 must be 64 slice")
	}

	return (*[64]byte)(unsafe.Pointer(&s))
}
