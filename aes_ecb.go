/**
 * En/Decrypt using the AES block cipher in ECB or CBC mode.
 *
 * In ECB mode, this is Equivalent to:
   KEY=59454c4c4f57205355424d4152494e45
   openssl enc -aes-128-ecb -nosalt -a -nopad -in t.txt -K $KEY -out t.txt.enc
   openssl enc -aes-128-ecb -nosalt -a -d -in t.txt.enc -K $KEY
 * Decrypting, OpenSSL ignores \n in base64'd input. The hex key is
 * ''.join('%x' % ord(c) for c in 'YELLOW SUBMARINE').
 */

package main

import (
    "log"
    "os"

    "github.com/droundy/goopt"

    "./blocks"
    "./aes_modes"
)


func main() {
  var decrypt = goopt.Flag(
      []string{"-d", "--decrypt"},
      []string{"-e", "--encrypt"},
      "Decrypt (instead of the default, encrypting).",
      "Encrypt.")
  var mode = goopt.Alternatives(
      []string{"-m", "--mode"},
      []string{"ecb", "cbc"},
      "Which mode of operation to use with the block cipher.")
  var format = goopt.Alternatives(
      []string{"-f", "--format"},
      []string{"hex", "base64"},
      "How to format the output ciphertext.")
  goopt.Description = func() string {
    return "En/Decrypt using AES in different modes of operation."
  }
  goopt.Parse(nil)

  if len(goopt.Args) != 1 {
    log.Fatalf(goopt.Synopsis())
  }
  key := blocks.FromString(goopt.Args[0])
  iv := blocks.FromBytes(make([]byte, 16, 16))
  if *decrypt {
    ciphertext := blocks.FromBase64Stream(os.Stdin)
    var plaintext *blocks.Blocks
    switch *mode {
    case "ecb":
      plaintext = aes_modes.EcbDecrypt(ciphertext, key)
    case "cbc":
      plaintext = aes_modes.CbcDecrypt(ciphertext, key, iv)
    default:
      panic(mode)
    }
    log.Printf("Decrypted:\n%s\n", plaintext.ToString())
  } else {
    plaintext := blocks.FromStringStream(os.Stdin)
    var ciphertext *blocks.Blocks
    switch *mode {
    case "ecb":
      ciphertext = aes_modes.EcbEncrypt(plaintext, key)
    case "cbc":
      ciphertext = aes_modes.CbcEncrypt(plaintext, key, iv)
    default:
      panic(*mode)
    }
    switch *format {
    case "hex":
      log.Printf("Encrypted:\n%s\n", ciphertext.ToHex())
    case "base64":
      log.Printf("Encrypted:\n%s\n", ciphertext.ToBase64())
    default:
      panic(*format)
    }
  }
}
