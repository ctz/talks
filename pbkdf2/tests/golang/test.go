package main

import "fmt"
import "encoding/hex"

import "crypto/sha1"
import "golang.org/x/crypto/pbkdf2"

func main() {
	const iterations = 1 << 22
	var k = pbkdf2.Key([]byte("password"), []byte("saltsalt"), iterations, 20, sha1.New)
	fmt.Printf("SHA1,%d,%s\n", iterations, hex.EncodeToString(k))
}
