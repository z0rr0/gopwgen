// Copyright (c) 2018, Alexander Zaytsev. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package main implements console password generator.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/z0rr0/gopwgen/pwgen"
)

func main() {
	help := flag.Bool("help", false, "show this help message and exit")
	noNumerals := flag.Bool("no-numerals", false,
		"don't include numbers in the generated passwords.")
	numerals := flag.Bool("numerals", true,
		"include at least one number in the password. This is the default option.")
	oneLine := flag.Bool("one-line", false,
		"print the generated passwords one per line.")
	noCapitalize := flag.Bool("no-capitalize", false,
		"don't bother to include any capital letters in the generated passwords.")
	symbols := flag.Bool("symbols", false,
		"include at least one special character in the password.")
	noVowels := flag.Bool("no-vowels", false,
		"Generate random passwords that do not contain vowels or numbers that might be mistaken for vowels. "+
			"It provides less secure passwords to allow system administrators to not have to worry "+
			"with random passwords acciden‐tally contain offensive substrings.")
	secure := flag.Bool("secure", false,
		"generate completely random, hard-to-memorize passwords. These should only be used for machine "+
			"passwords,  since otherwise  it's almost guaranteed that users will simply write the password on a "+
			"piece of paper taped to the monitor...")
	ambiguous := flag.Bool("ambiguous", false,
		"don't use characters that could be confused by the user when printed, "+
			"such as 'l' and '1', or '0' or 'O'.  This reduces the number of possible passwords significantly, "+
			"and as such reduces the quality of the  passwords.It may be useful for users who have bad vision, "+
			"but in general use of this option is not recommended.")
	removeChars := flag.String("remove-chars", "",
		"don't use the specified characters in password. "+
			"This option will disable the phomeme-based generator and uses the random password generator.")
	flag.Parse()

	if *help {
		fmt.Print("GoPwgen - generate pronounceable passwords\n\n")
		flag.PrintDefaults()
		return
	}
	args := flag.Args()
	pwLength, numPw, err := pwgen.ParseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: required integer arguments")
		return
	}
	pg, err := pwgen.New(
		pwLength, numPw, *removeChars,
		*noNumerals, *numerals, *oneLine, *noCapitalize, *ambiguous, *symbols, *noVowels, *secure,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return
	}
	fmt.Println(pg)
	pg.Print()
}
