package ssl

import "testing"

import "../blocks"


func TestEcbRoundTrip(t *testing.T) {
  expected_clear_text := blocks.FromString("pumpkin patch U!")
  expected_cipher_text := blocks.FromBase64("gY0wCsoqhcmxyNhqH6YE3w==")
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


func TestEcbSize(t *testing.T) {
  in := blocks.FromString("is commonly used")
  key := blocks.FromString("YELLOW SUBMARINE")
  out := EcbEncrypt(in, key)
  if in.Len() != out.Len() {
    t.Errorf("Encryption changed length: %d to %d.", in.Len(), out.Len())
  }
  round_trip := EcbDecrypt(out, key)
  if in.Len() != round_trip.Len() {
    t.Errorf("Decryption changed length: %d to %d.", in.Len(), round_trip.Len())
  }
}


func TestCbcRoundTrip(t *testing.T) {
  iv := blocks.FromString("YELLOW SUBMARINE")
  expected_clear_text := blocks.FromString("PUMPKIN PIE BOWL")
  expected_cipher_text := blocks.FromBase64("oJz6RDQ/SW+QKkYsdULvcg==")
  key := blocks.FromString("YELLOW SUBMARINE")

  cipher_text := CbcEncrypt(expected_clear_text, key, iv)
  if cipher_text.ToBase64() != expected_cipher_text.ToBase64() {
    t.Errorf(
        "Expected encryption as %q, but got %q.",
        expected_cipher_text.ToBase64(), cipher_text.ToBase64())
  }

  clear_text := CbcDecrypt(cipher_text, key, iv)
  if clear_text.ToString() != expected_clear_text.ToString() {
    t.Errorf(
        "Expected decryption as %q, but got %q.",
        expected_clear_text.ToString(), clear_text.ToString())
  }
}
