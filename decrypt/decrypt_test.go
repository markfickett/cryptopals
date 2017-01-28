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
