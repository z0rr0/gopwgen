[![GoDoc](https://godoc.org/github.com/z0rr0/gopwgen/pwgen?status.svg)](https://godoc.org/github.com/z0rr0/gopwgen/pwgen)  [![Build Status](https://travis-ci.com/z0rr0/gopwgen.svg?branch=master)](https://travis-ci.com/z0rr0/gopwgen)

# gopwgen

GoPwGen - generate pronounceable passwords

It's a go clone of Linux tool [pwgen](https://linux.die.net/man/1/pwgen).

## Usage

```bash
./gopwgen 10 20
ArQVS202eL zJK4JapKtd xbYDSzy1I0 Ya69eJMfo0 E7DVA6tIaM lhgCre7ja6 6fCLjYfQjL fEt6kivIVt
iCQJR7B6Of vb4yYUrON6 6GPW6cPcOu N2GA3mtD9K 8OG41kIh66 RZh1IHIl7E qTvzVL1qJk 18FP3yuzd2
5B0K4le9MM 3qcdCoKNX3 J9eNFc42KD P53HzsIBNv


./gopwgen -help
GoPwgen - generate pronounceable passwords

  -ambiguous
        don't use characters that could be confused by the user when printed, such as 'l' and '1', or '0' or 'O'.  This reduces the number of possible passwords significantly, and as such reduces the quality of the  passwords.It may be useful for users who have bad vision, but in general use of this option is not recommended.
  -help
        show this help message and exit
  -no-capitalize
        don't bother to include any capital letters in the generated passwords.
  -no-numerals
        don't include numbers in the generated passwords.
  -no-vowels
        Generate random passwords that do not contain vowels or numbers that might be mistaken for vowels. It provides less secure passwords to allow system administrators to not have to worry with random passwords acciden‐tally contain offensive substrings.
  -numerals
        include at least one number in the password. This is the default option. (default true)
  -one-line
        print the generated passwords one per line.
  -remove-chars string
        don't use the specified characters in password. This option will disable the phomeme-based generator and uses the random password generator.
  -secure
        generate completely random, hard-to-memorize passwords. These should only be used for machine passwords,  since otherwise  it's almost guaranteed that users will simply write the password on a piece of paper taped to the monitor...
  -sha1 string
        will use the sha1's hash of given file and the optional seed to create password.It will allow you to compute the same password later, if you remember the file, seed, and pwgen's options used. ie: pwgen -H ~/your_favorite.mp3#your@email.com gives a list of possibles passwords for your pop3 account, and you can ask this list again and again.
    
        WARNING: The  passwords  generated  using this option are not very random.If you use this option, make sure the attacker can not obtain a copy of the file.Also, note that the name of the file may be easily available from the ~/.history or ~/.bash_history file.
  -symbols
        include at least one special character in the password.
```

## Build

```bash
go install github.com/z0rr0/gopwgen
```

## Test

```bash
go test -v github.com/z0rr0/gopwgen/pwgen
```

Coverage, race detection and benchmarks:

```bash
go test -v -race -cover -coverprofile=coverage.out -trace trace.out -benchmem -bench=. github.com/z0rr0/gopwgen/pwgen

goos: linux
goarch: amd64
pkg: github.com/z0rr0/gopwgen/pwgen
BenchmarkNew-4                       200           6660014 ns/op           19542 B/op        607 allocs/op
BenchmarkOnePassword-4            200000              9321 ns/op              16 B/op          2 allocs/op
BenchmarkNewSecure-4                 100          19503809 ns/op           33390 B/op       3007 allocs/op
BenchmarkOnePasswordSecure-4       20000             60037 ns/op             136 B/op         17 allocs/op
PASS
coverage: 99.2% of statements
ok      github.com/z0rr0/gopwgen/pwgen  13.441s

# show reports
go tool cover -html=coverage.out
go tool trace pwgen.test trace.out
```

## License

This source code is governed by a MIT license that can be found in the [LICENSE](https://github.com/z0rr0/gopwgen/blob/master/LICENSE) file.