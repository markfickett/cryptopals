package encodings

import "fmt"
import "testing"


func TestBase64EncodeAligned(t *testing.T) {
  // "Man", from https://en.wikipedia.org/wiki/Base64
  actual_b64 := EncodeBase64([]byte{0x4d, 0x61, 0x6e})
  expected_b64 := "TWFu"
  if actual_b64 != expected_b64 {
    t.Error(fmt.Sprintf("expected %q but got %q", expected_b64, actual_b64))
  }
}


func TestBase64EncodPadded(t *testing.T) {
  actual_b64 := EncodeBase64([]byte{0x4d, 0x61})
  expected_b64 := "TWE="
  if actual_b64 != expected_b64 {
    t.Error(fmt.Sprintf("expected %q but got %q", expected_b64, actual_b64))
  }
}


func TestHexDecode(t *testing.T) {
  input_hex := "49276d206b696c6c696e6720796f757220627261696e206c696b652061207" +
      "06f69736f6e6f7573206d757368726f6f6d"
  expected_b64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2" +
      "hyb29t"
  actual_b64 := EncodeBase64(DecodeHex(input_hex))
  if actual_b64 != expected_b64 {
    t.Error(fmt.Sprintf("expected %q but got %q.", expected_b64, actual_b64))
  }
}
