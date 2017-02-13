/**
 * SSL-based en/decryption.
 */

package ssl

import "log"

// Use "go get <imported path below>" to fetch the library.
// https://sosedoff.com/2015/05/22/data-encryption-in-go-using-openssl.html
import "github.com/spacemonkeygo/openssl"

import "../blocks"


func EcbDecrypt(cipher_text *blocks.Blocks, key *blocks.Blocks) *blocks.Blocks {
  cipher, err := openssl.GetCipherByName("aes-128-ecb")
  if err != nil {
    panic("Unable to find cipher!")
  }
  ctx, err := openssl.NewDecryptionCipherCtx(
      cipher,
      nil,  // no engine
      key.ToBytes(),
      nil)  // no initialization vector
  if err != nil {
    panic("Unable to create context for encryption!")
  }

  plaintext, err := ctx.DecryptUpdate(cipher_text.ToBytes())
  if err != nil {
    log.Fatalf("Initial decryption failed: %q", err)
  }
  finalplaintext, err := ctx.DecryptFinal()
  if err != nil {
    log.Fatalf("Final decryption failed: %q", err)
  }
  plaintext = append(plaintext, finalplaintext...)
  return blocks.FromBytes(plaintext)
}
