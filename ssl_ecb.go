/**
 * En/Decrypt using OpenSSL ECB. Equivalent to:
   KEY=59454c4c4f57205355424d4152494e45
   openssl enc -aes-128-ecb -nosalt -a -in test.txt -K $KEY -out test.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in test.txt.enc -K $KEY
 * Decrypting, OpenSSL ignores \n in base64'd input. The hex key is
 * ''.join('%x' % ord(c) for c in 'YELLOW SUBMARINE').
 *
 * https://cryptopals.com/sets/1/challenges/7
 */

package main

import "flag"
import "log"
import "os"

import "./blocks"
import "./ssl"


func main() {
  decrypt_ptr := flag.Bool("d", false, "If specified, decrypt instead of encrypting.")
  flag.Parse()
  if len(flag.Args()) != 1 {
    log.Fatalf("Usage: %s [-d] key < input.txt", os.Args[0])
  }
  key := blocks.FromString(flag.Args()[0])
  if *decrypt_ptr {
    cipher_text := blocks.FromBase64Stream(os.Stdin)
    clear_text := ssl.EcbDecrypt(cipher_text, key)
    log.Printf("Decrypted:\n%s\n", clear_text.ToString())
  } else {
    clear_text := blocks.FromStringStream(os.Stdin)
    cipher_text := ssl.EcbEncrypt(clear_text, key)
    log.Printf("Encrypted:\n%s\n", cipher_text.ToBase64())
  }
}
