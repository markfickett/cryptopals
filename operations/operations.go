/**
 * Operations on byte streams.
 */

package operations

import "bytes"
import "fmt"


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
