/**
 * Decrypt repeating-key XOR. https://cryptopals.com/sets/1/challenges/6
 */

package main

import "bytes"
import "log"
import "os"

import "./blocks"
import "./xor_crypt"


func main() {
  ciphertext := blocks.FromBase64Stream(os.Stdin)
  key_size := xor_crypt.FindKeySize(ciphertext)
  log.Printf("Guessed key size %d.\n", key_size)
  ciphertext.SetBlockSize(key_size)
  transposed := ciphertext.Transposed()
  var key_buf bytes.Buffer
  for i := 0; i < key_size; i++ {
    _, key_byte, _ := xor_crypt.XorDecrypt(transposed.Block(i))
    key_buf.WriteByte(key_byte)
    //log.Printf("\tkey byte %d:\t0x%x (%s)\n", i, key_byte, string(key_byte))
  }
  key := blocks.FromBytesBuffer(key_buf)
  log.Printf("Full key: %q\n", key.ToString())
  cleartext := ciphertext.Xor(key)
  log.Printf("Decrypted text:\n%s\n", cleartext.ToString())
}
