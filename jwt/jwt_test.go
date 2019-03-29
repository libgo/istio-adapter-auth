package jwt

import (
	"testing"
)

func TestJWT(t *testing.T) {
	c := &Claims{}

	c.Refresh()

	c.IssuedAt = c.IssuedAt - refExp*2

	token := c.Sign()

	t.Log(token)

	err := Parse(token, c)
	if err != nil {
		t.Fatal(err)
	}

	c.IssuedAt = 1

	if !c.NeedRefresh() {
		t.Fatal("must need refresh")
	}

	token = c.Sign()

	err = Parse(token, c)
	if err == nil {
		t.Fatal("err should not nil")
	}
}
