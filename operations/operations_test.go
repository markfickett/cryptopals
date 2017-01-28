package operations

import "fmt"
import "testing"

import "../encodings"


func TestXor(t *testing.T) {
  a := "1c0111001f010100061a024b53535009181c"
  b := "686974207468652062756c6c277320657965"
  expected := "746865206b696420646f6e277420706c6179"

  actual := encodings.EncodeHex(
      Xor(encodings.DecodeHex(a), encodings.DecodeHex(b)))
  if expected != actual {
    t.Error(fmt.Sprintf("%s ^ %s = %s but got %s", a, b, expected, actual))
  }
}
