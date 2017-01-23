/**
 * XOR two hex strings.
 */

package main

import "fmt"
import "os"

import "./encodings"
import "./operations"

func main() {
  operations.SelfTest()

  if len(os.Args) != 3 {
    panic(fmt.Sprintf("Usage: %s HEX_TEXT HEX_TEXT", os.Args[0]))
  }
  fmt.Println(encodings.EncodeHex(operations.Xor(
      encodings.DecodeHex(os.Args[1]),
      encodings.DecodeHex(os.Args[2]))))
}
