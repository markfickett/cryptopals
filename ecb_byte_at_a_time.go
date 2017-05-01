/**
 * Decrypt ECB-encrypted data by using a consistent-key encrypter.
 * https://cryptopals.com/sets/2/challenges/12
 *
 * The premise is that we have a black-box encrypter, and we can't access the
 * plaintext being encrypted but we can prepend our own plaintext to it.
 */

package main

import (
  "crypto/aes"
  "log"

  "./blocks"
  "./aes_modes"
)


type BlackBox struct {
  plaintext *blocks.Blocks
  key *blocks.Blocks
}


func NewBlackBox() *BlackBox {
  secret_plaintext := blocks.FromBase64(
      "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
      "YnkK")
  secret_key := blocks.RandomBlock(aes.BlockSize)
  return &BlackBox{plaintext: secret_plaintext, key: secret_key}
}


func (b *BlackBox) EncryptWithPrefix(prefix *blocks.Blocks) *blocks.Blocks {
  full_plaintext := prefix.Copy()
  full_plaintext.Append(b.plaintext)
  return aes_modes.EcbEncrypt(full_plaintext, b.key)
}


func find_block_size(bb *BlackBox) int {
  repeating := blocks.FromString("a")
  last_encrypted_str := bb.EncryptWithPrefix(repeating).ToString()
  for {
    repeating.Append(blocks.FromString("a"))
    encrypted_str := bb.EncryptWithPrefix(repeating).ToString()
    candidate_size := repeating.Len() - 1
    if last_encrypted_str[:candidate_size] == encrypted_str[:candidate_size] {
      return candidate_size
    }
    last_encrypted_str = encrypted_str
  }
}


func main() {
  black_box := NewBlackBox()
  block_size := find_block_size(black_box)
  log.Printf("Found black-box encrypter's block size: %d.", block_size)
}
