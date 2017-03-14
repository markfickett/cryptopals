/**
 * Encrypt using a random key and either ECB or CBC, and detect which was used.
 * https://cryptopals.com/sets/2/challenges/11
 *
 * This depends on specially crafted input which repeats the same 16-byte
 * cleartext block more than once (even with an arbitrary 5-10 byte prefix).
 */

package main

import (
    "log"

    "./blocks"
    "./aes_modes"
)


func main() {
  plaintext := blocks.FromString(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
  ciphertext := aes_modes.RandomEncrypt(plaintext)
  var mode_used string

  min_dist, avg_dist := ciphertext.GetMinimumAndAverageHammingDistance()
  log.Printf("Hamming Distance:\tmin: %f\tavg: %f", min_dist, avg_dist)

  if min_dist <= 0.0 {
    mode_used = "ECB"
  } else {
    mode_used = "CBC (by process of elimination)"
  }
  log.Printf(
      "Encrypted (%d bytes):\n%s\nEncryption mode determined to be %s.",
      ciphertext.Len(), ciphertext.ToBase64(), mode_used)
}
