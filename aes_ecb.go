/**
 * En/Decrypt using the AES block cipher in ECB mode. Equivalent to:
   KEY=59454c4c4f57205355424d4152494e45
   openssl enc -aes-128-ecb -nosalt -a -nopad -in t.txt -K $KEY -out t.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in t.txt.enc -K $KEY
 * Decrypting, OpenSSL ignores \n in base64'd input. The hex key is
 * ''.join('%x' % ord(c) for c in 'YELLOW SUBMARINE').
 *
 * https://cryptopals.com/sets/1/challenges/7
 */

package main

import "flag"
import "log"
import "os"

import "./blocks"
import "./aes_modes"


func main() {
  decrypt_ptr := flag.Bool(
      "d", false, "If specified, decrypt instead of encrypting.")
  flag.Parse()
  if len(flag.Args()) != 1 {
    log.Fatalf("Usage: %s [-d] key < input.txt", os.Args[0])
  }
  key := blocks.FromString(flag.Args()[0])
  if *decrypt_ptr {
    ciphertext := blocks.FromBase64Stream(os.Stdin)
    plaintext := aes_modes.EcbDecrypt(ciphertext, key)
    log.Printf("Decrypted:\n%s\n", plaintext.ToString())
  } else {
    plaintext := blocks.FromStringStream(os.Stdin)
    ciphertext := aes_modes.EcbEncrypt(plaintext, key)
    log.Printf("Encrypted:\n%s\n", ciphertext.ToBase64())
  }
}
