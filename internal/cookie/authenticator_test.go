package cookie

import (
	cryptorand "crypto/rand"
	"testing"
)

var additionalCookieData = []byte("foo")

func TestOkCookie(t *testing.T) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	cookie, _ := a.Sign(nil, additionalCookieData)
	if !a.Verify(cookie, additionalCookieData) {
		t.Fatal("verification failed")
	}
}

func TestAdditionalCookieDataSpoof(t *testing.T) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	cookie, _ := a.Sign(nil, additionalCookieData)
	if a.Verify(cookie, []byte("bar")) {
		t.Fatal("verification succeeded for different additional data")
	}
}

func TestTamperedCookie(t *testing.T) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	cookie, _ := a.Sign(nil, additionalCookieData)
	cookie[len(cookie)-1] = 0
	if a.Verify(cookie, additionalCookieData) {
		t.Fatal("verification succeeded for a tampered cookie")
	}
}

func TestTruncatedCookie(t *testing.T) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	cookie, _ := a.Sign(nil, additionalCookieData)
	for i := range cookie {
		if a.Verify(append([]byte(nil), cookie[:i]...), additionalCookieData) {
			t.Fatalf("verification succeeded for a truncated cookie of length %v", i)
		}
	}
}

func BenchmarkCookieSign(b *testing.B) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	dst := make([]byte, 40)

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		a.Sign(dst[:0], additionalCookieData)
	}
}

func BenchmarkOptimisticCookieVerification(b *testing.B) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	cookie, _ := a.Sign(nil, additionalCookieData)

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !a.Verify(cookie, additionalCookieData) {
			b.Fatal("verification failed")
		}
	}
}

func BenchmarkPessimisticCookieVerification(b *testing.B) {
	a, _ := NewAuthenticator(cryptorand.Reader)
	cookie := make([]byte, 40)

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if a.Verify(cookie, additionalCookieData) {
			b.Fatal("verification succeeded")
		}
	}
}
