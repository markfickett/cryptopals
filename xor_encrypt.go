/**
 * Encrypt cleartext by XORing it with a multi-byte key.
 * https://cryptopals.com/sets/1/challenges/5
 */

package main

import "fmt"
import "io"
import "os"

import "./encodings"
import "./operations"


func main() {
  if len(os.Args) != 2 {
    panic(fmt.Sprintf("Usage: %s key < input_lines.txt", os.Args[0]))
  }
  key := []byte(os.Args[1])

  buf := make([]byte, 16)
  reader := io.Reader(os.Stdin)
  offset := 0
  n, _ := io.ReadFull(reader, buf)
  for n > 0 {
    fmt.Printf(
        "%s\n",
        encodings.EncodeHex(
            operations.Xor(operations.Offset(key, offset), buf[:n])))
    offset += n
    n, _ = io.ReadFull(reader, buf)
  }
}
