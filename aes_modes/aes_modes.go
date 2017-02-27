/**
 * AES-based en/decryption modes.
 */

package aes_modes

import "crypto/aes"
import "crypto/rand"
import "fmt"
import "log"
import "math/big"

import "../blocks"


/**
 * Uses the AES block cipher in ECB mode to encrypt. Pads any partial.
 * https://cryptopals.com/sets/1/challenges/7
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */
func EcbEncrypt(plaintext *blocks.Blocks, key *blocks.Blocks) *blocks.Blocks {
  cipher, err := aes.NewCipher(key.ToBytes())
  if err != nil {
    panic(err)
  }
  if plaintext.BlockSize() != aes.BlockSize {
    panic(fmt.Sprintf(
        "Plaintext block size %d does not match AES block sizes %d.",
        plaintext.BlockSize(), aes.BlockSize))
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


func rand_int(n int) int {
  v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
  if err != nil {
    panic(err)
  }
  return int(v.Int64())
}


/**
 * Encrypts data using CBC or ECB mode, using a random key (and IV if
 * applicable). Pad the incoming plaintext (before and after) with 5-10 random
 * bytes
 */
func RandomEncrypt(raw_plaintext *blocks.Blocks) *blocks.Blocks {
  key := blocks.RandomBlock(aes.BlockSize)
  plaintext := blocks.RandomBlock(5 + rand_int(5))
  plaintext.Append(raw_plaintext)
  plaintext.Append(blocks.RandomBlock(5 + rand_int(5)))
  plaintext.SetBlockSize(aes.BlockSize)
  if rand_int(2) > 0 {
    log.Printf(
        "Encrypting %q=>%q with ECB using %s.",
        raw_plaintext.ToString(), plaintext.ToString(), key.ToHex())
    return EcbEncrypt(plaintext, key)
  } else {
    iv := blocks.RandomBlock(aes.BlockSize)
    log.Printf(
        "Encrypting %q=>%q with CBC using %s and %s.",
        raw_plaintext.ToString(), plaintext.ToString(), key.ToHex(), iv.ToHex())
    return CbcEncrypt(plaintext, key, iv)
  }
}
