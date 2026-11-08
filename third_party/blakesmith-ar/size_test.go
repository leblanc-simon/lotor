package ar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

// archive construit une archive ar d'un membre dont le champ de taille est size, suivi de
// body.
func archive(size, body string) []byte {
	var b bytes.Buffer
	b.WriteString(GLOBAL_HEADER)
	fmt.Fprintf(&b, "%-16s%-12s%-6s%-6s%-8s%-10s`\n", "control.tar.gz", "0", "0", "0", "100644", size)
	b.WriteString(body)
	return b.Bytes()
}

// GO-2026-6905 : une taille négative laissait un reste négatif, et Read paniquait en
// découpant le tampon de l'appelant. Next doit refuser l'en-tête.
func TestNegativeSizeIsRejected(t *testing.T) {
	for _, size := range []string{"-1", "-2", "-999999999"} {
		r := NewReader(bytes.NewReader(archive(size, "xxxxxxxxxxxxxxxx\n")))
		h, err := r.Next()
		if !errors.Is(err, ErrInvalidSize) {
			t.Fatalf("taille %s : Next = %+v, %v ; attendu ErrInvalidSize", size, h, err)
		}
		if _, err := io.ReadAll(r); err != io.EOF && err != nil {
			t.Fatalf("taille %s : Read après le refus : %v", size, err)
		}
	}
}

// Un membre de taille nulle reste valide (rien à lire).
func TestZeroSizeMember(t *testing.T) {
	r := NewReader(bytes.NewReader(archive("0", "")))
	h, err := r.Next()
	if err != nil || h.Size != 0 {
		t.Fatalf("Next = %+v, %v", h, err)
	}
	if data, err := io.ReadAll(r); err != nil || len(data) != 0 {
		t.Fatalf("ReadAll = %q, %v", data, err)
	}
}
