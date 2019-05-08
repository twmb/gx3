package gx3

import (
	"strconv"
	"testing"

	"github.com/twmb/gx3/testdata"
)

func TestCanon(t *testing.T) {
	var in []byte
	for i := uint64(0); i < 10000; i++ {
		exp := testdata.XXH3_64bits_withSeed(in, i)
		got := SeedSum64(in, i)

		if exp != got {
			t.Errorf("failure at len %d", i)
		}
		in = append(in, byte(i))
	}
}

func BenchmarkSizes(b *testing.B) {
	buf := make([]byte, 1<<20)
	for length := 32; length <= cap(buf); length *= 2 {
		b.Run(strconv.Itoa(length), func(b *testing.B) {
			buf = buf[:length]
			b.SetBytes(int64(length))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				SeedSum64(buf, 0)
			}
		})
	}
}
