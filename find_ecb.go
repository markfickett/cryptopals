/**
 * Find which ciphertext is ECB-encrypted.
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
  overall_min_dist := math.Inf(1)
  min_line := -1
  min_ciphertext := ""
  for scanner.Scan() {
    ciphertext := blocks.FromHex(scanner.Text())
    min_dist, avg_dist := ciphertext.GetMinimumAndAverageHammingDistance()
    annotation := ""
    if min_dist < overall_min_dist {
      overall_min_dist = min_dist
      annotation = " *"
      min_line = line_num
      min_ciphertext = ciphertext.ToBase64()
    }
    log.Printf(
        "line %d\tavg %f\tmin %f%s", line_num, avg_dist, min_dist, annotation)
    line_num++
  }
  log.Printf(
      "Line %d had minimum inter-block Hamming distance %f.\n%q\n",
      min_line, overall_min_dist, min_ciphertext)
}
