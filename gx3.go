package gx3

import "math/bits"

const (
	keysetDefaultSize = 48

	prime32 = 2654435761

	prime1 = 11400714785074694791
	prime2 = 14029467366897019727
	prime3 = 1609587929392839161
	prime4 = 9650029242287828579
	prime5 = 2870177450012600261

	stripeLen  = 64
	stripeElts = stripeLen / 4
	accNB      = stripeLen / 8

	nbKeys   = (keysetDefaultSize - stripeElts) / 2
	blockLen = stripeLen * nbKeys
)

var kkey = [keysetDefaultSize]uint32{
	0xb8fe6c39, 0x23a44bbe, 0x7c01812c, 0xf721ad1c,
	0xded46de9, 0x839097db, 0x7240a4a4, 0xb7b3671f,
	0xcb79e64e, 0xccc0e578, 0x825ad07d, 0xccff7221,
	0xb8084674, 0xf743248e, 0xe03590e6, 0x813a264c,
	0x3c2852bb, 0x91c300cb, 0x88d0658b, 0x1b532ea3,
	0x71644897, 0xa20df94e, 0x3819ef46, 0xa9deacd8,
	0xa8fa763f, 0xe39c343f, 0xf9dcbbc7, 0xc70b4f1d,
	0x8a51e04b, 0xcdb45931, 0xc89f7ec9, 0xd9787364,

	0xeac5ac83, 0x34d3ebc3, 0xc581a0ff, 0xfa1363eb,
	0x170ddd51, 0xb7f0da49, 0xd3165526, 0x29d4689e,
	0x2b16be58, 0x7d47a1fc, 0x8ff8b8d1, 0x7ad031ce,
	0x45cb3a8f, 0x95160428, 0xafd7fbca, 0xbb4b407e,
}

// The canonical source uses kkey in two ways: one as a *byte, with offsets
// multiples of 8, and the other as a []uint64, with offsets of 1.
//
// Where canon uses *byte, we divide by 4 to get to the index into a []uint32.
// Where canon uses uint64, we mul by 2.
func readKey64(idx byte) uint64 {
	return uint64(kkey[idx+1])<<32 | uint64(kkey[idx])
}

func mul128fold64(l, r uint64) uint64 {
	hi, lo := bits.Mul64(l, r)
	return hi ^ lo
}

func avalanche(v uint64) uint64 {
	v ^= v >> 37
	v *= prime3
	v ^= v >> 32
	return v
}

func len1to3_64(b []byte, l int, seed uint64) uint64 {
	c3 := b[l-1]
	c2 := b[l>>1]
	c1 := b[0]
	l1 := uint32(c1) + (uint32(c2) << 8)
	l2 := uint32(l) + (uint32(c3) << 2)
	hi, lo := uint32(seed>>32), uint32(seed)
	v1 := l1 + lo + kkey[0]
	v2 := l2 + hi + kkey[1]
	v := uint64(v1) * uint64(v2)
	return avalanche(v)
}

func len4to8_64(b []byte, l int, seed uint64) uint64 {
	l1 := le32(b)
	l2 := le32(b[l-4:])
	l64 := uint64(l1) + uint64(l2)<<32
	keyed := l64 ^ readKey64(0) + seed
	mix := uint64(l) + mul128fold64(keyed, prime1)
	return avalanche(mix)
}

func len9to16_64(b []byte, l int, seed uint64) uint64 {
	l2 := le64(b[l-8:]) ^ (readKey64(2) - seed)
	l1 := le64(b) ^ (readKey64(0) + seed)
	acc := uint64(l) + l1 + l2 + mul128fold64(l1, l2)
	return avalanche(acc)
}

func len0to16_64(b []byte, l int, seed uint64) uint64 {
	switch len(b) {
	case 0:
		return seed
	case 1, 2, 3:
		return len1to3_64(b, l, seed)
	case 4, 5, 6, 7, 8:
		return len4to8_64(b, l, seed)
	}
	return len9to16_64(b, l, seed)
}

func mix16B(b []byte, keyIdx byte, seed uint64) uint64 {
	l1 := le64(b)
	l2 := le64(b[8:])

	v1 := l1 ^ (readKey64(keyIdx) + seed)
	v2 := l2 ^ (readKey64(keyIdx+2) - seed)

	return mul128fold64(v1, v2)
}

func accumulate512(acc []uint64, b []byte, keyIdx byte) {
	for i := byte(0); i < accNB; i++ {
		kVal := readKey64(2*i + keyIdx)
		bVal := le64(b[8*i:])
		bKey := kVal ^ bVal
		acc[i] += uint64(uint32(bKey)) * uint64(uint32(bKey>>32))
		acc[i] += bVal
	}
}

func scrambleAcc(acc []uint64) {
	keyBase := byte(keysetDefaultSize - stripeElts)
	for i := byte(0); i < accNB; i++ {
		k := readKey64(keyBase + 2*i)
		a := acc[i]
		a ^= a >> 47
		a ^= k
		a *= prime32
		acc[i] = a
	}
}

func accumulate(acc []uint64, b []byte, nbStripes byte) {
	var keyIdx byte
	for n := byte(0); n < nbStripes; n++ {
		accumulate512(acc, b[n*stripeLen:], keyIdx)
		keyIdx += 2
	}
}

func hashLong(acc []uint64, b []byte, l int) {
	nbBlocks := l / blockLen

	for n := 0; n < nbBlocks; n++ {
		accumulate(acc, b[n*blockLen:], nbKeys)
		scrambleAcc(acc)
	}

	nbStripes := byte(l % blockLen / stripeLen)
	accumulate(acc, b[nbBlocks*blockLen:], nbStripes)

	if l&(stripeLen-1) != 0 {
		accumulate512(acc, b[l-stripeLen:], nbStripes*2)
	}
}

func mix2Accs(acc []uint64, key []uint32) uint64 {
	k2 := uint64(key[3])<<32 | uint64(key[2])
	k1 := uint64(key[1])<<32 | uint64(key[0])

	l := acc[0] ^ k1
	r := acc[1] ^ k2
	return mul128fold64(l, r)
}

func mergeAccs(acc []uint64, key []uint32, start uint64) uint64 {
	r := start

	r += mix2Accs(acc[0:], key[0:])
	r += mix2Accs(acc[2:], key[4:])
	r += mix2Accs(acc[4:], key[8:])
	r += mix2Accs(acc[6:], key[12:])

	return avalanche(r)
}

func initKeySeed(key []uint32, seed uint64) {
	s1 := uint32(seed)
	s2 := uint32(seed >> 32)
	for i := 0; i < keysetDefaultSize; i += 4 {
		key[i+0] = kkey[i+0] + s1
		key[i+1] = kkey[i+1] - s2
		key[i+2] = kkey[i+2] + s2
		key[i+3] = kkey[i+3] - s1
	}
}

func hashLong64(b []byte, l int, seed uint64) uint64 {
	var acc = [accNB]uint64{
		seed,
		prime1, prime2, prime3, prime4, prime5,
		-seed,
		0,
	}
	hashLong(acc[:], b, l)

	var key [keysetDefaultSize]uint32
	initKeySeed(key[:], seed)
	return mergeAccs(acc[:], key[:], uint64(l)*prime1)
}

func SeedSum64(b []byte, seed uint64) uint64 {
	l := len(b)
	if l <= 16 {
		return len0to16_64(b, l, seed)
	}

	acc := uint64(l) * prime1
	if l > 32 {
		if l > 64 {
			if l > 96 {
				if l > 128 {
					return hashLong64(b, l, seed)
				}

				acc += mix16B(b[48:], 96/4, seed)
				acc += mix16B(b[l-64:], 112/4, seed)
			}

			acc += mix16B(b[32:], 64/4, seed)
			acc += mix16B(b[l-48:], 80/4, seed)
		}

		acc += mix16B(b[16:], 32/4, seed)
		acc += mix16B(b[l-32:], 48/4, seed)
	}

	acc += mix16B(b, 0, seed)
	acc += mix16B(b[l-16:], 16/4, seed)

	return avalanche(acc)
}
