/**
 * Find which byte block is ECB-encrypted.
 * https://cryptopals.com/sets/1/challenges/8
 */

package main

import "bufio"
import "log"
import "math"
import "os"

import "./blocks"


func main() {
  if len(os.Args) > 1 {
    log.Fatalf("Usage: %s < input_base64.txt]", os.Args[0])
  }

  scanner := bufio.NewScanner(os.Stdin)
  line_num := 1
  min_dist := math.Inf(1)
  min_line := -1
  min_ciphertext := ""
  for scanner.Scan() {
    ciphertext := blocks.FromHex(scanner.Text())
    dist := ciphertext.GetAverageHammingDistance()
    annotation := ""
    if dist < min_dist {
      min_dist = dist
      annotation = " *"
      min_line = line_num
      min_ciphertext = ciphertext.ToBase64()
    }
    log.Printf("line %d\tavg distance %f%s", line_num, dist, annotation)
    line_num++
  }
  log.Printf(
      "Line %d had minimum inter-block Hamming distance %f.\n%q\n",
      min_line, min_dist, min_ciphertext)
}
