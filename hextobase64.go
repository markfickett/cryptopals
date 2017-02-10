package main

import "fmt"
import "os"

import "./blocks"

func main() {
  if len(os.Args) != 2 {
    panic(fmt.Sprintf("Usage: %s TEXT_TO_CONVERT", os.Args[0]))
  }
  fmt.Println(blocks.FromHex(os.Args[1]).ToBase64())
}
