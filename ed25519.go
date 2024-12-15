package jwt

import (
	"crypto"
	"crypto/sha512"
	"errors"
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

// var sha512Pool *objPool[hash.Hash]

// var digestPool *objPool[[]byte]

type PrivateKeyEd struct {
	key    [privateKeyLen]byte
	s      edwards25519.Scalar
	prefix [32]byte
}

type PublicKeyEd struct {
	a      edwards25519.Point
	public [publicKeyLen]byte
}

func NewPrivateKey(privBytes [64]byte) *PrivateKeyEd {

	priv := new(PrivateKeyEd)

	h := _sum512_(privBytes[:32])
	clamp(h[:])

	s, err := priv.s.SetUniformBytes(h[:])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	memcopy_avx2_32(unsafe.Pointer(&priv.prefix[0]), unsafe.Pointer(&h[0]))

	A := (&edwards25519.Point{}).ScalarBaseMult(s)

	memcopy_avx2_32(unsafe.Pointer(&priv.key[0]), unsafe.Pointer(&privBytes[32]))
	memcopy_avx2_32(unsafe.Pointer(&priv.key[32]), unsafe.Pointer(&A.Bytes()[0]))

	return priv
}

func NewPublicKey(pubBytes *[publicKeyLen]byte) *PublicKeyEd {

	pub := new(PublicKeyEd)
	if _, err := pub.a.SetBytes(pubBytes[:]); err != nil {
		panic("ed25519: internal error: setting point failed")
	}
	memcopy_avx2_32(unsafe.Pointer(&pub.public[0]), unsafe.Pointer(&pubBytes[0]))
	return pub
}

func (p *PrivateKeyEd) Public() *PublicKeyEd {

	var publicKey [publicKeyLen]byte

	memcopy_avx2_32(unsafe.Pointer(&publicKey[0]), unsafe.Pointer(&p.key[32]))

	return NewPublicKey(&publicKey)
}

func NewKeyFromSeed(seed [32]byte) *PrivateKeyEd {

	priv := new(PrivateKeyEd)

	newKeyFromSeed(priv, &seed)

	return priv
}

func newKeyFromSeed(privateKey *PrivateKeyEd, seed *[seedLen]byte) {

	h := _sum512_(seed[:])
	clamp(h[:])
	// reduceModOrder(h[:], false)

	// h[0] &= 248
	// h[31] &= 63
	// h[31] |= 64

	// var hbytes [64]byte

	// memcopy_avx2_32(unsafe.Pointer(&hbytes[0]), unsafe.Pointer(&h[0]))
	// copy_AVX2_32(res[:32], h[:32])
	// s, err := privateKey.s.SetBytesWithClamping(h[:32])
	// if err != nil {
	// 	panic("ed25519: internal error: setting scalar failed")
	// }
	s, err := privateKey.s.SetUniformBytes(h[:])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	// fmt.Println(hbytes)
	// s, err := edwards25519.NewScalar().SetUniformBytes(res)
	// if err != nil {
	// 	panic("ed25519: internal error: setting scalar failed")
	// }
	memcopy_avx2_32(unsafe.Pointer(&privateKey.prefix[0]), unsafe.Pointer(&h[0]))
	// fmt.Println(privateKey.prefix)

	A := (&edwards25519.Point{}).ScalarBaseMult(s)

	memcopy_avx2_32(unsafe.Pointer(&privateKey.key[0]), unsafe.Pointer(&seed[0]))
	memcopy_avx2_32(unsafe.Pointer(&privateKey.key[32]), unsafe.Pointer(&A.Bytes()[0]))

	// bufferPool.Put(hbytes)

}

func (priv *PrivateKeyEd) __Sign__(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature [signatureSize]byte, err error) {
	hash := opts.HashFunc()

	context := ""
	if opts, ok := opts.(*_Options); ok {
		context = opts.Context
	}
	switch {
	case hash == crypto.SHA512: // Ed25519ph
		if l := len(message); l != sha512.Size {
			return signature, errors.New("ed25519: bad Ed25519ph message hash length: " + strconv.Itoa(l))
		}
		if l := len(context); l > 255 {
			return signature, errors.New("ed25519: bad Ed25519ph context length: " + strconv.Itoa(l))
		}

		// fmt.Println(len(signature))
		var signature [64]byte

		sign(priv, message, domPrefixPh, context, &signature)

		// _ = signature[:0]

		return signature, nil
	case hash == crypto.Hash(0) && context != "": // Ed25519ctx
		if l := len(context); l > 255 {
			return signature, errors.New("ed25519: bad Ed25519ctx context length: " + strconv.Itoa(l))
		}
		var signature [64]byte
		sign(priv, message, domPrefixCtx, context, &signature)

		// bytePools[0].clear()

		return signature, nil
	case hash == crypto.Hash(0): // Ed25519
		return Sign(priv, message, domPrefixPure, ""), nil
	default:
		return signature, errors.New("ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

func Sign(privateKey *PrivateKeyEd, message []byte, domPrefix, context string) [64]byte {
	var signature [signatureSize]byte

	sign(privateKey, message, domPrefix, context, &signature)

	return signature

}

func sign(privateKey *PrivateKeyEd, message []byte, domPrefix, context string, s0 *[64]byte) {
	//seed = privateKey.key[:seedLen]
	publicKey := privateKey.key[seedLen:]

	// h := _sum512_(seed)

	// h[0] &= 248
	// h[31] &= 63
	// h[31] |= 64

	// fmt.Println(prefix)

	mh := NewDigest() //2
	if domPrefix != domPrefixPure {
		mh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		mh.Write([]byte{byte(len(context))})
		mh.Write(lowlevelfunctions.StringToBytes(context))
	}
	mh.Write(privateKey.prefix[:])
	mh.Write(message)
	var messageDigest = digestPool.Get()

	messageDigest = mh.Sum(messageDigest)
	r, err := edwards25519.NewScalar().SetUniformBytes(messageDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	// mh.Reset()
	// sha512Pool.Put(mh)

	R := (&edwards25519.Point{}).ScalarBaseMult(r)
	Rbytes := R.Bytes()

	kh := NewDigest() // 3
	if domPrefix != domPrefixPure {
		kh.Write(lowlevelfunctions.StringToBytes(domPrefix))
		kh.Write([]byte{byte(len(context))})
		kh.Write(lowlevelfunctions.StringToBytes(context))
	}
	kh.Write(Rbytes)
	kh.Write(publicKey)
	kh.Write(message)
	var hramDigest = digestPool.Get()

	hramDigest = kh.Sum(hramDigest)
	k, err := edwards25519.NewScalar().SetUniformBytes(hramDigest)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	// kh.Reset()
	// sha512Pool.Put(kh)
	messageDigest = messageDigest[:0]
	hramDigest = hramDigest[:0]
	digestPool.Put(messageDigest)
	digestPool.Put(hramDigest)

	S := edwards25519.NewScalar().MultiplyAdd(k, &privateKey.s, r)

	memcopy_avx2_32(unsafe.Pointer(&s0[0]), unsafe.Pointer(&Rbytes[0]))

	memcopy_avx2_32(unsafe.Pointer(&s0[32]), unsafe.Pointer(&S.Bytes()[0]))

	// copy_AVX2_32(s0[:32], Rbytes)
	// copy_AVX2_32(s0[32:], S.Bytes())

}

func Verify__(publicKey *PublicKeyEd, message, sig []byte) bool {
	return verify(publicKey, message, sig, domPrefixPure, "")
}

func verify(publicKey *PublicKeyEd, message, sig []byte, domPrefix, context string) bool {

	if len(sig) != signatureSize || sig[63]&signatureFlagsMask != 0 {
		return false
	}

	// A, err := (&edwards25519.Point{}).SetBytes(publicKey)
	// if err != nil {
	// 	return false
	// }

	kh := NewDigest() // 1
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
	kh.Write(publicKey.public[:])
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
	minusA := (&edwards25519.Point{}).Negate(&publicKey.a)
	R := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(k, minusA, S)
	// kh.Reset()
	// sha512Pool.Put(kh)
	hramDigest = hramDigest[:0]
	digestPool.Put(hramDigest)

	return bytes.Equal(sig[:32], R.Bytes())
}

func __VerifyWithOptions__(publicKey *PublicKeyEd, message, sig []byte, opts *_Options) error {
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

func GenerateED25519(rand io.Reader) (*PublicKeyEd, *PrivateKeyEd, error) {
	return __generateKey__(rand)
}

func __generateKey__(rand io.Reader) (*PublicKeyEd, *PrivateKeyEd, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	var seed [32]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	// _ = seed[:0]

	// _ = publicKey[:0]

	var publicKey [publicKeyLen]byte
	memcopy_avx2_32(unsafe.Pointer(&publicKey[0]), unsafe.Pointer(&privateKey.key[32]))

	return NewPublicKey(&publicKey), privateKey, nil
}

func b_32(s []byte) [32]byte {
	return *(*[32]byte)(noescape(unsafe.Pointer(&s[0])))
}

func b_64(s []byte) *[64]byte {
	return (*[64]byte)(noescape(unsafe.Pointer(&s[0])))
}
