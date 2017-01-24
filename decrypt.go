/**
 * Decrypt ciphertext which has been XORed with a single byte key.
 * https://cryptopals.com/sets/1/challenges/3
 */

package main

import "bytes"
import "fmt"
import "os"

import "./encodings"
import "./operations"


/**
 * Returns a score for some text for how likely it is to be clear text.
 * The score is the number of Latin letters in the string.
 */
func get_score(text string) int {
  num_e := 0
  for _, c := range text {
    if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
      num_e += 1
    }
  }
  return num_e
}


func main() {
  if len(os.Args) != 2 {
    panic(fmt.Sprintf("Usage: %s TEXT_TO_DECRYPT", os.Args[0]))
  }
  cipher_text := encodings.DecodeHex(os.Args[1])
  clear_text := ""
  max_score := 0
  var best_key byte = 0x0
  for key := 0x0; key < (0x1 << 8); key++ {
    decrypted_text := string(operations.Xor(
        cipher_text,
        bytes.Repeat([]byte{ byte(key) }, len(cipher_text))))
    score := get_score(decrypted_text)
    if score > max_score {
      max_score = score
      best_key = byte(key)
      clear_text = decrypted_text
    }
  }
  fmt.Printf("Key 0x%x scored %d. %s\n", best_key, max_score, clear_text)
}
