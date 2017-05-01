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


func decrypt(black_box *BlackBox, block_size int) *blocks.Blocks {
  known_prefix := blocks.New()
  for {
    known_prefix.Append(blocks.FromString("*"))
    if known_prefix.Len() == block_size - 1 {
      break
    }
  }
  encrypted_with_unknown_byte := black_box.EncryptWithPrefix(known_prefix)
  matched := false
  for b := 0x0; b < (0x1 << 8); b++ {
    possible_next_prefix := known_prefix.Copy()
    possible_next_prefix.AppendByte(byte(b))
    encrypted_with_known_byte := black_box.EncryptWithPrefix(
        possible_next_prefix)
    matched = blocks.Equal(
        encrypted_with_known_byte.Block(0),
        encrypted_with_unknown_byte.Block(0))
    if matched {
      known_prefix = possible_next_prefix
      break
    }
  }

  return blocks.FromString(known_prefix.ToString()[block_size - 1:])
}


func main() {
  black_box := NewBlackBox()

  block_size := find_block_size(black_box)
  log.Printf("Found black-box encrypter's block size: %d.", block_size)

  repeated_block := blocks.RandomBlock(block_size)
  repeated_block.Append(repeated_block)
  repeated_encrypted := black_box.EncryptWithPrefix(repeated_block)
  repeated_encrypted.SetBlockSize(block_size)
  min_dist, _ := repeated_encrypted.GetMinimumAndAverageHammingDistance()
  if min_dist == 0 {
    log.Printf("Min Hamming dist with repeated block %f: ECB.", min_dist)
  } else {
    log.Fatalf("Min Hamming dist with repeated block %f. Not ECB?", min_dist)
  }

  log.Printf(
      "Decrypted secret plaintext: %s",
      decrypt(black_box, block_size).ToString())
}
