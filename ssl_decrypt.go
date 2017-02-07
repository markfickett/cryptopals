/**
 * Decrypt using OpenSSL block cipher. Equivalent to:
   openssl enc -aes-128-ecb -nosalt -a -in test.txt -k "YELLOW SUBMARINE" \
       -out test.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in test.txt.enc -k "YELLOW SUBMARINE"
 * (Decrypting, OpenSSL ignores \n in base64'd input.)
 *
 * https://sosedoff.com/2015/05/22/data-encryption-in-go-using-openssl.html
 */

package main

import "log"

import "github.com/spacemonkeygo/openssl"

import "./encodings"

func main() {
  ciphertext_b64 := "EF+K58xQEs8UTb6s7f+oKQ=="  // "test"
  ciphertext := encodings.DecodeBase64(ciphertext_b64)

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
  log.Printf("Created context: %s", ctx)

  plaintext, err := ctx.DecryptUpdate(ciphertext)
  if err != nil {
    log.Printf("Initial decryption failed: %q", err)
    panic(err)
  }
  log.Printf("Decrypted some: %q", plaintext)
  finalplaintext, err := ctx.DecryptFinal()
  if err != nil {
    log.Printf("Final decryption failed: %q", err)
    panic(err)
  }
  plaintext = append(plaintext, finalplaintext...)

  log.Printf("Decoded %q as %q.\n", ciphertext_b64, plaintext)
}
