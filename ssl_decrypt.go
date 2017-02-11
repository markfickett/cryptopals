/**
 * Decrypt using OpenSSL block cipher. Equivalent to:
   KEY=59454c4c4f57205355424d4152494e45
   openssl enc -aes-128-ecb -nosalt -a -in test.txt -K $KEY -out test.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in test.txt.enc -K $KEY
 * Decrypting, OpenSSL ignores \n in base64'd input. The hex key is
 * ''.join('%x' % ord(c) for c in 'YELLOW SUBMARINE').
 *
 * https://sosedoff.com/2015/05/22/data-encryption-in-go-using-openssl.html
 *
 * https://cryptopals.com/sets/1/challenges/7
 */

package main

import "bufio"
import "log"
import "os"

// Use "go get <imported path below>" to fetch the library.
import "github.com/spacemonkeygo/openssl"

import "./blocks"


func main() {
  if len(os.Args) > 2 || (len(os.Args) == 2 && os.Args[1] != "test") {
    log.Fatalf("Usage: %s [test|< input_base64.txt]", os.Args[0])
  }

  cipher_text := blocks.New()
  if len(os.Args) == 2 {
    cipher_text = blocks.FromBase64("WVmOEnGj4iK3UDEZVvVYZw==")  // "test"
    log.Printf("Decoding sample: %q\n", cipher_text.ToBase64())
  } else {
    cipher_text := blocks.FromBase64Stream(os.Stdin)
  }

  key := []byte("YELLOW SUBMARINE")

  cipher, err := openssl.GetCipherByName("aes-128-ecb")
  if err != nil {
    panic("Unable to find cipher!")
  }
  ctx, err := openssl.NewDecryptionCipherCtx(
      cipher,
      nil,  // no engine
      key,
      nil)  // no initialization vector
  if err != nil {
    panic("Unable to create context for encryption!")
  }

  plaintext, err := ctx.DecryptUpdate(cipher_text.ToBytes())
  if err != nil {
    log.Printf("Initial decryption failed: %q", err)
    panic(err)
  }
  finalplaintext, err := ctx.DecryptFinal()
  if err != nil {
    log.Printf("Final decryption failed: %q", err)
    panic(err)
  }
  plaintext = append(plaintext, finalplaintext...)

  log.Printf("Decoded as:\n%s\n", plaintext)
}
