package ssl

import "testing"

import "../blocks"


func TestEcbRoundTrip(t *testing.T) {
  expected_clear_text := blocks.FromString("test\n")
  expected_cipher_text := blocks.FromBase64("WVmOEnGj4iK3UDEZVvVYZw==")
  key := blocks.FromString("YELLOW SUBMARINE")

  clear_text := EcbDecrypt(expected_cipher_text, key)
  if clear_text.ToString() != expected_clear_text.ToString() {
    t.Errorf(
        "Expected decryption as %q, but got %q.",
        expected_clear_text.ToString(), clear_text.ToString())
  }

  cipher_text := EcbEncrypt(expected_clear_text, key)
  if cipher_text.ToBase64() != expected_cipher_text.ToBase64() {
    t.Errorf(
        "Expected encryption as %q, but got %q.",
        expected_cipher_text.ToBase64(), cipher_text.ToBase64())
  }
}
