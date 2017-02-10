/**
 * XOR two hex strings.
 */

package main

import "fmt"
import "os"

import "./blocks"

func main() {
  if len(os.Args) != 3 {
    panic(fmt.Sprintf("Usage: %s HEX_TEXT HEX_TEXT", os.Args[0]))
  }
  fmt.Println(
      blocks.FromHex(os.Args[1]).Xor(blocks.FromHex(os.Args[2])).ToHex())
}
