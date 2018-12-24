// Copyright (c) 2018, Alexander Zaytsev. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package pwgen implements password generator structures and methods.

package pwgen

import (
	"bytes"
	"errors"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
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
		pwLength, 10000, "", "",
		false, true, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedString := "PwGen <length: 8, number:10000> " +
		"from abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if s := pg.String(); s != expectedString {
		t.Errorf("unexpected string; %v", s)
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
		pwLength, 10000, "", "",
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
		pwLength, 10000, "", "",
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
		pwLength, 10000, "", "",
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
		pwLength, 10000, "", "",
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
		pwLength, 10000, "", "",
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
		pwLength, 1000, "", "",
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
		pwLength, 1000, "", "",
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
		pwLength, 10000, removeChars, "",
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

func TestNewFail(t *testing.T) {
	_, err := New(
		0, 10000, "", "",
		false, false, false,
		false, false, false, false, false,
	)
	if err == nil {
		t.Errorf("no expected error for zero password length")
	}
	_, err = New(
		16, 0, "", "",
		false, false, false,
		false, false, false, false, false,
	)
	if err == nil {
		t.Errorf("no expected error for zero passwords numbers")
	}
	removeChars := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_, err = New(
		16, 100, removeChars, "",
		false, false, false,
		false, false, false, false, false,
	)
	if err == nil {
		t.Errorf("no expected error - no symbols")
	}
	_, err = New(
		16, 100, "", "/root/bad_123",
		false, false, false,
		false, false, false, false, false,
	)
	if err == nil {
		t.Errorf("no expected error - failed file read")
	}
}

func TestSHA1(t *testing.T) {
	pwLength := 16
	fileName := "pwgen_test.tmp"
	fullName := path.Join(os.TempDir(), fileName)

	f, err := os.Create(fullName)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("abcdef")
	if err != nil {
		t.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		t.Errorf("can not close file: %v", err)
	}

	defer func() {
		err = os.Remove(fullName)
		if err != nil {
			t.Fatal(err)
		}
	}()
	// 1st generation
	pg, err := New(
		pwLength, 10000, "", fullName,
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
	// 2nd generation
	pg, err = New(
		pwLength, 10000, "", fullName,
		false, false, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	ch = pg.Passwords()
	s2 := make([]string, pg.numPw)
	i = 0
	for p := range ch {
		s2[i] = p
		i++
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			t.Errorf("not equal %v == %v", s1[i], s2[i])
		}
	}
}

func TestOneLinePrint(t *testing.T) {
	var (
		buffer bytes.Buffer
		out    string
	)
	pg, err := New(
		1, 1, "", "",
		false, false, true,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	values := [][2]int{
		{5, 3},
		{1, 1},
		{15, 30},
		{5, 150},
		{15, 70},
	}
	for i, params := range values {
		pg.pwLength, pg.numPw = params[0], params[1]
		err := pg.Print(&buffer)
		if err != nil {
			t.Fatal(err)
		}
		out = buffer.String()
		if lo, le := len(out), pg.numPw*(1+pg.pwLength)+1; lo != le {
			t.Errorf("[%v] invalid length [number=%v], real not equal expected %v = %v", i, pg.numPw, lo, le)
		}
		buffer = bytes.Buffer{}
	}
}

func TestMultiLinesPrint(t *testing.T) {
	var (
		buffer bytes.Buffer
		out    string
		w, le  int
	)
	pg, err := New(
		1, 1, "", "",
		false, false, false,
		false, false, false, false, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	values := [][2]int{
		{5, 3},
		{1, 1},
		{15, 30},
		{5, 150},
		{15, 70},
		{100, 2},
	}
	for _, params := range values {
		pg.pwLength, pg.numPw = params[0], params[1]
		err = pg.Print(&buffer)
		if err != nil {
			t.Fatal(err)
		}
		out = buffer.String()

		le = pg.numPw*(1+pg.pwLength) + 1
		w = screenWidth / pg.pwLength
		if w == 0 {
			w = 1
			le--
		} else {
			if (pg.numPw % w) == 0 {
				le--
			}
		}
		if lo := len(out); lo != le {
			t.Errorf("invalid length [number=%v], real not equal expected %v = %v", pg.numPw, lo, le)
		}
		buffer = bytes.Buffer{}
	}
}

func TestParseArgs(t *testing.T) {
	valueError := errors.New("error")
	values := []struct {
		in  []string
		e   error
		out [2]int
	}{
		{[]string{}, nil, [2]int{defaultPwLength, defaultNumPw}},
		{[]string{"12"}, nil, [2]int{12, defaultNumPw}},
		{[]string{"12", "23"}, nil, [2]int{12, 23}},
		{[]string{"12", "23", "7"}, nil, [2]int{12, 23}},
		{[]string{"12", "23", "7", "8", "9"}, nil, [2]int{12, 23}},
		{[]string{"a"}, valueError, [2]int{0, 0}},
		{[]string{"2", "a"}, valueError, [2]int{0, 0}},
		{[]string{"-1"}, valueError, [2]int{0, 0}},
		{[]string{"5", "-5"}, valueError, [2]int{0, 0}},
		{[]string{"a", "-5"}, valueError, [2]int{0, 0}},
		{[]string{"-5", "5"}, valueError, [2]int{0, 0}},
	}
	for i, value := range values {
		l, n, err := ParseArgs(value.in)
		switch {
		case (err != nil) && (value.e == nil):
			t.Errorf("<%v> gotten unexpected error: %v", value.in, err)
		case (err == nil) && (value.e != nil):
			t.Errorf("<%v> no unexpected error: %v", value.in, value.e)
		default:
			if l != value.out[0] {
				t.Errorf("failed length [%v]: %v", i, l)
			}
			if n != value.out[1] {
				t.Errorf("failed numbers [%v]: %v", i, n)
			}
		}

	}
}

func BenchmarkNew(b *testing.B) {
	for n := 0; n < b.N; n++ {
		pg, err := New(
			defaultPwLength, defaultNumPw, "", "",
			false, false, false,
			false, false, false, false, false,
		)
		if err != nil {
			b.Fatal(err)
		}
		err = pg.Print(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	pg, err := New(
		defaultPwLength, defaultNumPw, "", "",
		false, false, false,
		false, false, false, false, false,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pg.Generate()
	}
}

func BenchmarkNewSecure(b *testing.B) {
	for n := 0; n < b.N; n++ {
		pg, err := New(
			defaultPwLength, defaultNumPw, "", "",
			false, false, false,
			false, false, false, false, true,
		)
		if err != nil {
			b.Fatal(err)
		}
		err = pg.Print(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateSecure(b *testing.B) {
	pg, err := New(
		defaultPwLength, defaultNumPw, "", "",
		false, false, false,
		false, false, false, false, true,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pg.Generate()
	}
}
