package main

import "fmt"
import "os"

import "./encodings"

func main() {
  encodings.SelfTest()
  if len(os.Args) != 2 {
    panic(fmt.Sprintf("Usage: %s TEXT_TO_CONVERT", os.Args[0]))
  }
  fmt.Println(encodings.EncodeBase64(encodings.DecodeHex(os.Args[1])))
}
