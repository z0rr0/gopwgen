// Copyright (c) 2020, Alexander Zaytsev. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package pwgen implements password generator structures and methods.
package pwgen

import (
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"time"
)

const (
	defaultPwLength = 8   // default password length
	defaultNumPw    = 160 // default number of generated passwords
	screenWidth     = 80  // screen width for output by columns

	// passwords alphabets
	pwDigits    = "0123456789"
	pwLowers    = "abcdefghijklmnopqrstuvwxyz"
	pwUppers    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pwSymbols   = "!\"#$%&\\'()*+,-./:;<=>?@[\\]^_`{|}~"
	pwAmbiguous = "B8G6I1l0OQDS5Z2"
	pwVowels    = "01aeiouyAEIOUY"
)

// PwGen is main struct for passwords generation by required rules.
type PwGen struct {
	pwLength, numPw               int
	noNumerals, numerals, oneLine bool
	noCapitalize, ambiguous       bool
	symbols, secure               bool
	random                        *rand.Rand
	chars                         []byte
}

// CryptoRandSource represents a source of uniformly-distributed random int64 values in the range [0, 1<<63).
type CryptoRandSource struct{}

// Int63 returns a non-negative random 63-bit integer as an int64 from CryptoRandSource.
func (CryptoRandSource) Int63() int64 {
	var b [8]byte
	_, err := crand.Read(b[:])
	if err != nil {
		panic(err) // fail - can't continue
	}
	return int64(binary.LittleEndian.Uint64(b[:]) & (1<<63 - 1))
}

// Seed is fake CryptoRandSource Seed implementation for Source interface.
func (CryptoRandSource) Seed(int64) {}

// ParseArgs parses string arguments to length and number of passwords.
func ParseArgs(args []string) (int, int, error) {
	var err error
	pwLength := defaultPwLength
	numPw := defaultNumPw

	n := len(args)
	switch {
	case n == 1:
		pwLength, err = strconv.Atoi(args[0])
		if err != nil {
			return 0, 0, err
		}
		if pwLength < 1 {
			return 0, 0, errors.New("password length is to be positive")
		}
		return pwLength, numPw, nil
	case n >= 2:
		pwLength, err = strconv.Atoi(args[0])
		if err != nil {
			return 0, 0, err
		}
		if pwLength < 1 {
			return 0, 0, errors.New("password length is to be positive")
		}
		numPw, err = strconv.Atoi(args[1])
		if err != nil {
			return 0, 0, err
		}
		if numPw < 1 {
			return 0, 0, errors.New("passwords numbers is to be positive")
		}
	}
	return pwLength, numPw, nil
}

// randomSource chooses random source, random or pseudo-random.
func randomSource(secure bool, seed int64) rand.Source {
	if secure {
		return CryptoRandSource{}
	}
	if seed != 0 {
		return rand.NewSource(seed)
	}
	return rand.NewSource(time.Now().UnixNano())
}

// New returns new password generation structure.
func New(pwLength, numPw int, removeChars, sha1File string,
	noNumerals, numerals, oneLine, noCapitalize, ambiguous, symbols, noVowels, secure bool) (*PwGen, error) {

	var seed int64
	if pwLength < 1 {
		return nil, errors.New("password length should be greater than 0")
	}
	if numPw < 1 {
		return nil, errors.New("password length should be greater than 0")
	}
	if sha1File != "" {
		f, err := os.Open(sha1File)
		if err != nil {
			return nil, err
		}
		h := sha1.New()
		_, err = io.Copy(h, f)
		if err != nil {
			_ = f.Close() // ignore error
			return nil, err
		}
		seed = int64(binary.LittleEndian.Uint64(h.Sum(nil)[:]))
		err = f.Close()
		if err != nil {
			return nil, err
		}
	}
	source := randomSource(secure, seed)
	random := rand.New(source)

	if ambiguous {
		removeChars += pwAmbiguous
	}
	if noVowels {
		removeChars += pwVowels
	}
	if noNumerals {
		removeChars += pwDigits
	}

	pg := &PwGen{
		pwLength, numPw,
		noNumerals, numerals, oneLine,
		noCapitalize, ambiguous,
		symbols, secure,
		random, nil,
	}
	chars, err := pg.alphabet([]byte(removeChars))
	if err != nil {
		return nil, err
	}
	pg.chars = chars
	return pg, nil
}

// String returns representation string of PwGen.
func (pg *PwGen) String() string {
	return fmt.Sprintf("PwGen <length: %v, number:%v> from %v", pg.pwLength, pg.numPw, string(pg.chars))
}

func (pg *PwGen) choiceFromString(alphabet string) byte {
	return alphabet[pg.random.Intn(len(alphabet))]
}

func (pg *PwGen) choice(alphabet []byte) byte {
	return alphabet[pg.random.Intn(len(alphabet))]
}

// Generate returns a new random password.
func (pg *PwGen) Generate() string {
	password := make([]byte, pg.pwLength)

	n := pg.pwLength - 1
	if pg.symbols {
		password[n] = pg.choiceFromString(pwSymbols)
		n--
	}
	if !pg.noNumerals && pg.numerals && (n > 0) {
		password[n] = pg.choiceFromString(pwDigits)
		n--
	}
	for i := n; i >= 0; i-- {
		password[i] = pg.choice(pg.chars)
	}
	pg.random.Shuffle(pg.pwLength, func(i, j int) {
		password[i], password[j] = password[j], password[i]
	})
	return string(password)
}

// Passwords returns a channel to generate needed number of passwords.
func (pg *PwGen) Passwords() chan string {
	c := make(chan string)
	go func() {
		for i := 0; i < pg.numPw; i++ {
			c <- pg.Generate()
		}
		close(c)
	}()
	return c
}

// Print outputs required passwords.
func (pg *PwGen) Print(out io.Writer) error {
	var ended bool
	ch := pg.Passwords()
	if pg.oneLine {
		// output as one line
		for p := range ch {
			_, err := fmt.Fprintf(out, "%s ", p)
			if err != nil {
				return err
			}
		}
	} else {
		// output by columns
		i, w := 0, screenWidth/pg.pwLength
		if w == 0 {
			w = 1
		}
		for p := range ch {
			i++
			ended = (i % w) == 0
			if ended {
				_, err := fmt.Fprintln(out, p)
				if err != nil {
					return err
				}
			} else {
				_, err := fmt.Fprintf(out, "%s ", p)
				if err != nil {
					return err
				}
			}
		}
	}
	// new line if it's needed
	if !ended {
		_, err := fmt.Fprintln(out)
		if err != nil {
			return err
		}
	}
	return nil
}

// alphabet returns byte slice of chars for passwords generation.
func (pg *PwGen) alphabet(removeChars []byte) ([]byte, error) {
	var result []byte

	chars := pwLowers
	if !pg.noNumerals {
		chars += pwDigits
	}
	if !pg.noCapitalize {
		chars += pwUppers
	}
	if pg.symbols {
		chars += pwSymbols
	}
	byteChars := []byte(chars)

	if rc := len(removeChars); rc > 0 {
		result = make([]byte, 0, len(byteChars))
		sort.Slice(removeChars, func(i, j int) bool { return removeChars[i] < removeChars[j] })
		for _, c := range byteChars {
			i := sort.Search(rc, func(i int) bool { return removeChars[i] >= c })
			// not found in removeChars, then include to the result
			if !(i < rc && removeChars[i] == c) {
				result = append(result, c)
			}
		}
	} else {
		result = byteChars
	}
	if len(result) < 1 {
		return nil, errors.New("no symbols for passwords generation")
	}
	return result, nil
}
