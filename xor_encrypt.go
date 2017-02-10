/**
 * Encrypt cleartext by XORing it with a multi-byte key.
 * https://cryptopals.com/sets/1/challenges/5
 */

package main

import "fmt"
import "io"
import "os"

import "./blocks"


func main() {
  if len(os.Args) != 2 {
    panic(fmt.Sprintf("Usage: %s key < input_lines.txt", os.Args[0]))
  }
  key := blocks.FromString(os.Args[1])
  text := blocks.New()

  buf := make([]byte, 16)
  reader := io.Reader(os.Stdin)
  n, _ := io.ReadFull(reader, buf)
  for n > 0 {
    text.AppendBytes(buf[:n])
    n, _ = io.ReadFull(reader, buf)
  }
  fmt.Printf(text.Xor(key).ToHex())
  fmt.Println()
}
