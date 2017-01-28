/**
 * Decrypt ciphertext which has been XORed with a single byte key.
 * https://cryptopals.com/sets/1/challenges/3
 */

package decrypt

import "../operations"


/**
 * Returns a score for some text for how likely it is to be English clear text.
 * The score is the number of Latin letters in the string.
 */
func GetScore(text string) int {
  score := 0
  for _, c := range text {
    if c >= 'a' && c <= 'z' {
      score += 2
    }
    if c >= 'A' && c <= 'Z' {
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
func XorDecrypt(cipher_text []byte) (int, byte, string) {
  clear_text := ""
  max_score := 0
  var best_key byte = 0x0
  for key := 0x0; key < (0x1 << 8); key++ {
    decrypted_text := string(operations.Xor([]byte{ byte(key) }, cipher_text))
    score := GetScore(decrypted_text)
    if score > max_score {
      max_score = score
      best_key = byte(key)
      clear_text = decrypted_text
    }
  }
  return max_score, best_key, clear_text
}
