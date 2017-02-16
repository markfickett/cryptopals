/**
 * Decrypt ciphertext which has been XORed with a single byte key.
 * https://cryptopals.com/sets/1/challenges/3 and 4
 *
 * Reads from stdin and brute-force decrypts lines. If given multiple lines,
 * finds the line with the highest score (most likelihood of decryption).
 */

package main

import "bufio"
import "log"
import "os"

import "./blocks"
import "./xor_crypt"


func main() {
  if len(os.Args) != 1 {
    log.Fatalf("Usage: %s < input_lines.txt", os.Args[0])
  }
  best_line_num := 0
  max_score := 0
  var best_key byte = 0x0
  best_text := ""

  scanner := bufio.NewScanner(os.Stdin)
  line_num := 1
  for scanner.Scan() {
    score, key, plaintext := xor_crypt.XorDecrypt(
        blocks.FromHex(scanner.Text()))
    if score > max_score {
      best_line_num = line_num
      max_score = score
      best_key = key
      best_text = plaintext
    }
    line_num++
  }
  log.Printf(
      "Line %d: key 0x%x scored %d\t%q\n",
      best_line_num, best_key, max_score, best_text)
}
