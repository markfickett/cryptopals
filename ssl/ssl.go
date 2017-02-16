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
func EcbEncrypt(plaintext *blocks.Blocks, key *blocks.Blocks) *blocks.Blocks {
  cipher, err := aes.NewCipher(key.ToBytes())
  if err != nil {
    panic(err)
  }
  if plaintext.BlockSize() != aes.BlockSize {
    panic("Block size mismatch.")
  }
  ciphertext := blocks.New()
  for i := 0; i < plaintext.NumBlocks(); i++ {
    plain_block := plaintext.BlockPadded(i).ToBytes()
    cipher_block := make([]byte, aes.BlockSize)
    cipher.Encrypt(cipher_block, plain_block)
    ciphertext.AppendBytes(cipher_block)
  }
  return ciphertext
}


/**
 * AES-decrypts blocks. Input must match AES block size and be full blocks.
 */
func EcbDecrypt(ciphertext *blocks.Blocks, key *blocks.Blocks) *blocks.Blocks {
  cipher, err := aes.NewCipher(key.ToBytes())
  if err != nil {
    panic(err)
  }
  if ciphertext.BlockSize() != aes.BlockSize {
    panic("Block size mismatch.")
  }
  plaintext := blocks.New()
  for i := 0; i < ciphertext.NumBlocks(); i++ {
    cipher_block := ciphertext.Block(i).ToBytes()
    if len(cipher_block) < ciphertext.BlockSize() {
      panic("Incomplete block.")
    }
    plain_block := make([]byte, aes.BlockSize)
    cipher.Decrypt(plain_block, cipher_block)
    plaintext.AppendBytes(plain_block)
  }
  return plaintext
}


/**
 * Encrypt using CBC mode.
 * https://cryptopals.com/sets/2/challenges/10
 */
func CbcEncrypt(
    plaintext *blocks.Blocks,
    key *blocks.Blocks,
    iv *blocks.Blocks) *blocks.Blocks {
  ciphertext := blocks.New()
  cipher_block := iv
  for i := 0; i < plaintext.NumBlocks(); i++ {
    plain_block := plaintext.BlockPadded(i)
    plain_block = plain_block.Xor(cipher_block)
    cipher_block = EcbEncrypt(plain_block, key)
    ciphertext.Append(cipher_block)
  }
  return ciphertext
}


func CbcDecrypt(
    ciphertext *blocks.Blocks,
    key *blocks.Blocks,
    iv *blocks.Blocks) *blocks.Blocks {
  plaintext := blocks.New()
  prev_cipher_block := iv
  for i := 0; i < ciphertext.NumBlocks(); i++ {
    cipher_block := ciphertext.Block(i)
    plain_block := EcbDecrypt(cipher_block, key)
    plain_block = plain_block.Xor(prev_cipher_block)
    prev_cipher_block = cipher_block
    plaintext.Append(plain_block)
  }
  return plaintext
}
