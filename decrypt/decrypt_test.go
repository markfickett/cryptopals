package decrypt

import "fmt"
import "strings"
import "testing"

import "../encodings"

func TestDecryptSingleByteXor(t *testing.T) {
  cipher_text := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e" +
      "783a393b3736"
  _, _, clear_text := XorDecrypt(encodings.DecodeHex(cipher_text))
  expected_word := "bacon"
  if !strings.Contains(clear_text, expected_word) {
    t.Error(fmt.Sprintf(
        "Sample text should have %q in it, but decrypted as %q.",
        expected_word, clear_text))
  }
}


func TestScore(t *testing.T) {
  non_english := "iU\x1chkZHXPIK\x16tXKAnQWs\x1bAD>XtbxIK"
  bad_score := GetScore(non_english)
  english := "Now that the party is jumping\n"
  good_score := GetScore(english)
  if bad_score >= good_score {
    t.Error(fmt.Sprintf(
        "bad %q scored %d >= good %q which scored %d",
        bad_score, non_english, good_score, english))
  }
}
