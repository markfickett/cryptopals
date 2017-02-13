package ssl

import "testing"

import "../blocks"

func TestEcbDecrypt(t *testing.T) {
  plaintext := EcbDecrypt(
      blocks.FromBase64("WVmOEnGj4iK3UDEZVvVYZw=="),
      blocks.FromString("YELLOW SUBMARINE"))
  expected_plaintext := "test\n"
  if plaintext.ToString() != expected_plaintext {
    t.Errorf(
        "Expected decryption as %q, but got %q.",
        expected_plaintext, plaintext.ToString())
  }
}
