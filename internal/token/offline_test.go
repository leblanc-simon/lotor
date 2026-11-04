package token

import (
	"testing"

	"leblanc.io/lotor/internal/offline"
)

// Le jeton qu'un agent tire hors ligne (inscription par archive, T23) a le format des
// jetons du serveur : même identifiant public, même empreinte du secret.
func TestOfflineTokenFormat(t *testing.T) {
	for range 50 {
		raw, pub, hash, err := offline.NewAgentToken()
		if err != nil {
			t.Fatal(err)
		}
		gotPub, gotHash, err := Parse(Agent, raw)
		if err != nil || gotPub != pub || gotHash != SecretHash(hash) {
			t.Fatalf("%s : %v", raw, err)
		}
		if p, h, err := offline.ParseToken("agt", raw); err != nil || p != pub || h != hash {
			t.Fatalf("relecture hors ligne : %v", err)
		}
	}
	issued, err := New(Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if p, h, err := offline.ParseToken("enr", issued.Plaintext); err != nil || p != issued.PublicID || SecretHash(h) != issued.Hash {
		t.Fatalf("jeton d'inscription : %v", err)
	}
	for _, bad := range []string{"", "lotor_agt_", "lotor_agt_x_y", "lotor_enr_" + issued.Plaintext[10:]} {
		if _, _, err := offline.ParseToken("agt", bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}
