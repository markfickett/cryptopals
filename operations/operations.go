/**
 * Operations on byte streams.
 */

package operations

import "fmt"
import "bytes"

import "../encodings"

// https://cryptopals.com/sets/1/challenges/2
func Xor(a []byte, b []byte) []byte {
  if len(a) != len(b) {
    panic(fmt.Sprintf(
        "Cannot xor byte streams of differing length: %d != %d.",
        len(a), len(b)))
  }
  var out bytes.Buffer
  for i, a_byte := range a {
    out.WriteByte(a_byte ^ b[i])
  }
  return out.Bytes()
}


func SelfTest() {
  a := "1c0111001f010100061a024b53535009181c"
  b := "686974207468652062756c6c277320657965"
  expected := "746865206b696420646f6e277420706c6179"

  actual := encodings.EncodeHex(
      Xor(encodings.DecodeHex(a), encodings.DecodeHex(b)))
  if expected != actual {
    panic(fmt.Sprintf("%s ^ %s = %s but got %s", a, b, expected, actual))
  }
}
