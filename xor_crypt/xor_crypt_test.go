package xor_crypt

import "fmt"
import "strings"
import "testing"

import "../encodings"
import "../operations"

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


func TestEncrypt(t *testing.T) {
  clear_text :=
      "Burning 'em, if you ain't quick and nimble\n" +
      "I go crazy when I hear a cymbal"
  expected_hex :=
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727" +
      "65272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028316528632630" +
      "2e27282f"
  key := "ICE"
  cipher_text := operations.Xor([]byte(key), []byte(clear_text))
  cipher_hex := encodings.EncodeHex(cipher_text)
  if cipher_hex != expected_hex {
    t.Error(fmt.Sprintf(
        "%q ^ %q encrypted as %q, should be %q",
        key, clear_text, cipher_hex, expected_hex))
  }
}
