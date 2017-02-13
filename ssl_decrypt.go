/**
 * Decrypt using OpenSSL block cipher. Equivalent to:
   KEY=59454c4c4f57205355424d4152494e45
   openssl enc -aes-128-ecb -nosalt -a -in test.txt -K $KEY -out test.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in test.txt.enc -K $KEY
 * Decrypting, OpenSSL ignores \n in base64'd input. The hex key is
 * ''.join('%x' % ord(c) for c in 'YELLOW SUBMARINE').
 *
 * https://cryptopals.com/sets/1/challenges/7
 */

package main

import "log"
import "os"

import "./blocks"
import "./ssl"


func main() {
  if len(os.Args) != 2 {
    log.Fatalf("Usage: %s key < input_base64.txt", os.Args[0])
  }
  cipher_text := blocks.FromBase64Stream(os.Stdin)
  key := blocks.FromString(os.Args[1])
  plaintext := ssl.EcbDecrypt(cipher_text, key)
  log.Printf("Decoded as:\n%s\n", plaintext.ToString())
}
