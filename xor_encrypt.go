/**
 * Encrypt cleartext by XORing it with a multi-byte key.
 * https://cryptopals.com/sets/1/challenges/5
 */

package main

import "io"
import "log"
import "os"

import "./blocks"


func main() {
  if len(os.Args) != 2 {
    log.Fatalf("Usage: %s key < input_lines.txt", os.Args[0])
  }
  key := blocks.FromString(os.Args[1])
  cleartext := blocks.FromStringStream(os.Stdin)
  log.Printf("%s\n", cleartext.Xor(key).ToHex())
}
