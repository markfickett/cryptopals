package aes_modes

import "testing"

import "../blocks"


func TestEcbRoundTrip(t *testing.T) {
  expected_cleartext := blocks.FromString("pumpkin patch U!")
  expected_ciphertext := blocks.FromBase64("gY0wCsoqhcmxyNhqH6YE3w==")
  key := blocks.FromString("YELLOW SUBMARINE")

  cleartext := EcbDecrypt(expected_ciphertext, key)
  if cleartext.ToString() != expected_cleartext.ToString() {
    t.Errorf(
        "Expected decryption as %q, but got %q.",
        expected_cleartext.ToString(), cleartext.ToString())
  }

  ciphertext := EcbEncrypt(expected_cleartext, key)
  if ciphertext.ToBase64() != expected_ciphertext.ToBase64() {
    t.Errorf(
        "Expected encryption as %q, but got %q.",
        expected_ciphertext.ToBase64(), ciphertext.ToBase64())
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
  expected_cleartext := blocks.FromString("PUMPKIN PIE BOWL")
  expected_ciphertext := blocks.FromBase64("oJz6RDQ/SW+QKkYsdULvcg==")
  key := blocks.FromString("YELLOW SUBMARINE")

  ciphertext := CbcEncrypt(expected_cleartext, key, iv)
  if ciphertext.ToBase64() != expected_ciphertext.ToBase64() {
    t.Errorf(
        "Expected encryption as %q, but got %q.",
        expected_ciphertext.ToBase64(), ciphertext.ToBase64())
  }

  cleartext := CbcDecrypt(ciphertext, key, iv)
  if cleartext.ToString() != expected_cleartext.ToString() {
    t.Errorf(
        "Expected decryption as %q, but got %q.",
        expected_cleartext.ToString(), cleartext.ToString())
  }
}
