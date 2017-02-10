/**
 * XOR two hex strings.
 */

package main

import "log"
import "os"

import "./blocks"

func main() {
  if len(os.Args) != 3 {
    log.Fatalf("Usage: %s HEX_TEXT HEX_TEXT", os.Args[0])
  }
  log.Printf(
      "%s\n",
      blocks.FromHex(os.Args[1]).Xor(blocks.FromHex(os.Args[2])).ToHex())
}
