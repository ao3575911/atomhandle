package handle

import "testing"

func TestParse(t *testing.T) {
	h, err := Parse("@adam/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if h.String() != "@adam/researcher" || h.DID() != "did:atom:adam/researcher" {
		t.Fatalf("%s %s", h, h.DID())
	}
	back, err := ParseDID(h.DID())
	if err != nil || back != h {
		t.Fatalf("%v %v", back, err)
	}
	ok := []string{"@a/b", "@a0/b-c", "@abc/a0"}
	for _, s := range ok {
		if _, err := Parse(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{"", "@", "adam/researcher", "@Adam/researcher", "@a/b/c", "@a/", "@/b", "@-a/b", "@a/-b", "@a/b-", "@a_b/c", "@ab/c.d", "did:atom:a/b"}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := ParseDID("did:atom:adam/researcher"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDID("did:web:adam/researcher"); err == nil {
		t.Fatal("wrong method")
	}
}

func FuzzParseHandle(f *testing.F) {
	f.Add("@adam/researcher")
	f.Add("@a/b")
	f.Add("")
	f.Add("@")
	f.Add("did:atom:adam/researcher")
	f.Fuzz(func(t *testing.T, s string) {
		h, err := Parse(s)
		if err != nil {
			return
		}
		if h.String() != s {
			t.Fatalf("round trip %q -> %q", s, h)
		}
		if _, err := ParseDID(h.DID()); err != nil {
			t.Fatal(err)
		}
	})
}
