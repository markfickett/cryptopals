package main

import "log"
import "os"

import "./blocks"

func main() {
  if len(os.Args) != 2 {
    log.Fatalf("Usage: %s TEXT_TO_CONVERT", os.Args[0])
  }
  log.Printf(blocks.FromHex(os.Args[1]).ToBase64())
}
