/**
 * Decrypt ciphertext which has been XORed with a single byte key.
 * https://cryptopals.com/sets/1/challenges/3
 */

package main

import "fmt"
import "os"

import "./decrypt"
import "./encodings"


func main() {
  if len(os.Args) != 2 {
    panic(fmt.Sprintf("Usage: %s TEXT_TO_DECRYPT", os.Args[0]))
  }
  score, key, clear_text := decrypt.XorDecrypt(encodings.DecodeHex(os.Args[1]))
  fmt.Printf("Key 0x%x scored %d. %s\n", key, score, clear_text)
}
