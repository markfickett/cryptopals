/**
 * Decrypt using OpenSSL block cipher. Equivalent to:
   KEY=59454c4c4f57205355424d4152494e45
   openssl enc -aes-128-ecb -nosalt -a -in test.txt -K $KEY -out test.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in test.txt.enc -K $KEY
 * Decrypting, OpenSSL ignores \n in base64'd input. The hex key is
 * ''.join('%x' % ord(c) for c in 'YELLOW SUBMARINE').
 *
 * https://sosedoff.com/2015/05/22/data-encryption-in-go-using-openssl.html
 */

package main

import "log"

// Use "go get <imported path below>" to fetch the library.
import "github.com/spacemonkeygo/openssl"

import "./blocks"


func main() {
  ciphertext := blocks.FromBase64("WVmOEnGj4iK3UDEZVvVYZw==")  // "test"
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

  plaintext, err := ctx.DecryptUpdate(ciphertext.ToBytes())
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

  log.Printf("Decoded %q as %q.\n", ciphertext.ToBase64(), plaintext)
}
