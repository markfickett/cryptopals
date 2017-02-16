/**
 * AES-based en/decryption modes.
 */

package ssl

import "crypto/aes"

import "../blocks"


/**
 * Uses the AES block cipher in ECB mode to encrypt. Pads any partial.
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */
func EcbEncrypt(clear_text *blocks.Blocks, key *blocks.Blocks) *blocks.Blocks {
  cipher, err := aes.NewCipher(key.ToBytes())
  if err != nil {
    panic(err)
  }
  if clear_text.BlockSize() != aes.BlockSize {
    panic("Block size mismatch.")
  }
  cipher_text := blocks.New()
  for i := 0; i < clear_text.NumBlocks(); i++ {
    clear_block := clear_text.BlockPadded(i).ToBytes()
    cipher_block := make([]byte, aes.BlockSize)
    cipher.Encrypt(cipher_block, clear_block)
    cipher_text.AppendBytes(cipher_block)
  }
  return cipher_text
}


/**
 * AES-decrypts blocks. Input must match AES block size and be full blocks.
 */
func EcbDecrypt(cipher_text *blocks.Blocks, key *blocks.Blocks) *blocks.Blocks {
  cipher, err := aes.NewCipher(key.ToBytes())
  if err != nil {
    panic(err)
  }
  if cipher_text.BlockSize() != aes.BlockSize {
    panic("Block size mismatch.")
  }
  clear_text := blocks.New()
  for i := 0; i < cipher_text.NumBlocks(); i++ {
    cipher_block := cipher_text.Block(i).ToBytes()
    if len(cipher_block) < cipher_text.BlockSize() {
      panic("Incomplete block.")
    }
    clear_block := make([]byte, aes.BlockSize)
    cipher.Decrypt(clear_block, cipher_block)
    clear_text.AppendBytes(clear_block)
  }
  return clear_text
}


/**
 * Encrypt using CBC mode.
 * https://cryptopals.com/sets/2/challenges/10
 */
func CbcEncrypt(
    clear_text *blocks.Blocks,
    key *blocks.Blocks,
    iv *blocks.Blocks) *blocks.Blocks {
  cipher_text := blocks.New()
  cipher_block := iv
  for i := 0; i < clear_text.NumBlocks(); i++ {
    clear_block := clear_text.BlockPadded(i)
    clear_block = clear_block.Xor(cipher_block)
    cipher_block = EcbEncrypt(clear_block, key)
    cipher_text.Append(cipher_block)
  }
  return cipher_text
}


func CbcDecrypt(
    cipher_text *blocks.Blocks,
    key *blocks.Blocks,
    iv *blocks.Blocks) *blocks.Blocks {
  clear_text := blocks.New()
  prev_cipher_block := iv
  for i := 0; i < cipher_text.NumBlocks(); i++ {
    cipher_block := cipher_text.Block(i)
    clear_block := EcbDecrypt(cipher_block, key)
    clear_block = clear_block.Xor(prev_cipher_block)
    prev_cipher_block = cipher_block
    clear_text.Append(clear_block)
  }
  return clear_text
}
