/**
 * Decrypt ciphertext which has been XORed with a single byte key.
 * https://cryptopals.com/sets/1/challenges/3
 */

package xor_crypt

import "math"

import "../blocks"


/**
 * Returns a score for some text for how likely it is to be English clear text.
 * The score is the number of Latin letters in the string.
 */
func GetScore(text string) int {
  score := 0
  for _, c := range text {
    if c >= 'a' && c <= 'z' {
      score += 3
    }
    if c >= 'A' && c <= 'Z' {
      score += 2
    }
    if c == ' ' || c == '\'' || c == '\n' || c == ',' || c == '-' {
      score += 1
    }
  }
  return score
}


/**
 * Returns a (score, key, cleartext) triple for decrypted text. Uses a single-
 * byte key to XOR text, and tries all single-byte keys to find the best scoring
 * decryption.
 */
func XorDecrypt(cipher_text *blocks.Blocks) (int, byte, string) {
  clear_text := ""
  max_score := 0
  var best_key byte = 0x0
  for key := 0x0; key < (0x1 << 8); key++ {
    decrypted_text := cipher_text.Xor(blocks.FromByte(byte(key))).ToString()
    score := GetScore(decrypted_text)
    if score > max_score {
      max_score = score
      best_key = byte(key)
      clear_text = decrypted_text
    }
  }
  return max_score, best_key, clear_text
}


func FindKeySize(cipher_text *blocks.Blocks) int {
  b := cipher_text.Copy()
  shortest := math.Inf(1)
  best_size := 0
  for size := 2; size < 40; size++ {
    b.SetBlockSize(size)
    avg_dist := b.GetAverageHammingDistance()
    debug_tag := ""
    if avg_dist < shortest {
      if best_size > 0 && size % best_size == 0 {
        // Multiples of the real key size also appear as good solutions.
        // Exclude them. (Mostly relevant with short keys.)
        debug_tag += " x"
      } else {
        debug_tag += " *"
        shortest = avg_dist
        best_size = size
      }
    }
    //log.Printf("key size %d\tdistance %f%s\n", size, avg_dist, debug_tag)
  }
  return best_size
}
