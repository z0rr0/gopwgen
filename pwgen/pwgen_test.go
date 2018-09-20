// Copyright (c) 2018, Alexander Zaytsev. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package pwgen implements password generator structures and methods.

package pwgen

import (
	"math/rand"
	"testing"
)

func any(password string, symbols ByteSlice) bool {
	for _, c := range []byte(password) {
		if symbols.Search(c) >= 0 {
			return true
		}
	}
	return false
}

func TestNumerals(t *testing.T) {
	pwLength := 8
	pg, err := New(
		pwLength, 10000, "",
		false, true, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(pwDigits)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if !any(p, symbols) {
			t.Errorf("%v not digits", p)
		}
	}
}

func TestNoNumerals(t *testing.T) {
	pwLength := 8
	pg, err := New(
		pwLength, 10000, "",
		true, false, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(pwDigits)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if any(p, symbols) {
			t.Errorf("%v found digits", p)
		}
	}
}

func TestNoCapitalize(t *testing.T) {
	pwLength := 16
	pg, err := New(
		pwLength, 10000, "",
		false, false, false,
		true, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(pwUppers)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if any(p, symbols) {
			t.Errorf("%v found upper", p)
		}
	}
}

func TestAmbiguous(t *testing.T) {
	pwLength := 16
	pg, err := New(
		pwLength, 10000, "",
		false, false, false,
		false, true, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(pwAmbiguous)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if any(p, symbols) {
			t.Errorf("%v found ambiguous", p)
		}
	}
}

func TestNoVowels(t *testing.T) {
	pwLength := 16
	pg, err := New(
		pwLength, 10000, "",
		false, false, false,
		false, false, false, true, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(pwVowels)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if any(p, symbols) {
			t.Errorf("%v found vowels", p)
		}
	}
}

func TestSymbols(t *testing.T) {
	pwLength := 8
	pg, err := New(
		pwLength, 10000, "",
		false, false, false,
		false, false, true, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(pwSymbols)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if !any(p, symbols) {
			t.Errorf("%v no symbols", p)
		}
	}
}

func TestNoSecure(t *testing.T) {
	pwLength := 64
	pg, err := New(
		pwLength, 1000, "",
		false, true, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	source := randomSource(false, 12345)
	pg.random = rand.New(source)

	ch := pg.Passwords()
	s1 := make([]string, pg.numPw)

	i := 0
	for p := range ch {
		s1[i] = p
		i++
	}

	source = randomSource(false, 12345)
	pg.random = rand.New(source)

	ch = pg.Passwords()
	s2 := make([]string, pg.numPw)

	i = 0
	for p := range ch {
		s2[i] = p
		i++
	}

	for i := range s1 {
		if s1[i] != s2[i] {
			t.Errorf("not equal %v != %v", s1[i], s2[i])
		}
	}
}

func TestSecure(t *testing.T) {
	pwLength := 64
	pg, err := New(
		pwLength, 1000, "",
		false, false, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	ch := pg.Passwords()
	s1 := make([]string, pg.numPw)

	i := 0
	for p := range ch {
		s1[i] = p
		i++
	}

	source := randomSource(true, 1)
	pg.random = rand.New(source)

	ch = pg.Passwords()
	s2 := make([]string, pg.numPw)

	i = 0
	for p := range ch {
		s2[i] = p
		i++
	}

	for i := range s1 {
		if s1[i] == s2[i] {
			t.Errorf("equal %v == %v", s1[i], s2[i])
		}
	}
}

func TestRemoveChars(t *testing.T) {	
	pwLength := 8
	removeChars := "abcdefghijklmnJKLMNOPQRSTUVWXYZ01234"
	pg, err := New(
		pwLength, 10000, removeChars,
		false, false, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	symbols := ByteSlice(removeChars)
	symbols.Sort()

	ch := pg.Passwords()
	for p := range ch {
		if l := len(p); l != pwLength {
			t.Errorf("%v failed len=%v", p, l)
		}
		if any(p, symbols) {
			t.Errorf("%v found removed char", p)
		}
	}
}
