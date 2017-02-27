/**
 * Encrypt using a random key and either ECB or CBC, and detect which was used.
 * https://cryptopals.com/sets/2/challenges/11
 */

package main

import (
    "log"
    "os"

    "./blocks"
    "./aes_modes"
)


func main() {
  plaintext := blocks.FromStringStream(os.Stdin)
  ciphertext := aes_modes.RandomEncrypt(plaintext)
  log.Printf("Encrypted:\n%s\n", ciphertext.ToBase64())
}
