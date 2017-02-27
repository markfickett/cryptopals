package blocks

import "testing"


func TestBase64EncodeAligned(t *testing.T) {
  // "Man", from https://en.wikipedia.org/wiki/Base64
  actual_b64 := FromBytes([]byte{0x4d, 0x61, 0x6e}).ToBase64()
  expected_b64 := "TWFu"
  if actual_b64 != expected_b64 {
    t.Errorf("expected %q but got %q", expected_b64, actual_b64)
  }
}


func TestBase64EncodPadded(t *testing.T) {
  actual_b64 := FromBytes([]byte{0x4d, 0x61}).ToBase64()
  expected_b64 := "TWE="
  if actual_b64 != expected_b64 {
    t.Errorf("expected %q but got %q", expected_b64, actual_b64)
  }
}


func TestBase64RoundTrip(t *testing.T) {
  start := FromBytes([]byte{0x1, 0x2, 0x3, 0x60, 0x61, 0x62})
  encoded := start.ToBase64()
  decoded := FromBase64(encoded)
  if !Equal(decoded, start) {
    t.Errorf(
        "input %q became %q doesn't match output %q",
        start.buf.String(), encoded, decoded.buf.String())
  }
}


func TestHexDecode(t *testing.T) {
  input_hex := "49276d206b696c6c696e6720796f757220627261696e206c696b652061207" +
      "06f69736f6e6f7573206d757368726f6f6d"
  expected_b64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2" +
      "hyb29t"
  actual_b64 := FromHex(input_hex).ToBase64()
  if actual_b64 != expected_b64 {
    t.Errorf("expected %q but got %q.", expected_b64, actual_b64)
  }
}


func TestXor(t *testing.T) {
  a := "1c0111001f010100061a024b53535009181c"
  b := "686974207468652062756c6c277320657965"
  expected := "746865206b696420646f6e277420706c6179"

  actual := FromHex(a).Xor(FromHex(b)).ToHex()
  if expected != actual {
    t.Errorf("%s ^ %s = %s but got %s", a, b, expected, actual)
  }
}


func TestHammingDistance(t *testing.T) {
  dist := FromString("this is a test").HammingDistance(
      FromString("wokka wokka!!!"))
  expected_dist := 37
  if dist != expected_dist {
    t.Errorf(
        "Hamming Distance is %d but got %d.", expected_dist, dist)
  }
}


func TestGetBlock(t *testing.T) {
  block_size := 4
  expected_num_blocks := 5
  b := FromString("abcdABCDqrstQRSTwx")
  b.SetBlockSize(block_size)
  if b.NumBlocks() != expected_num_blocks {
    t.Errorf(
        "%q in blocks of 4 should have %d blocks, reports %d.",
        b.ToString(), block_size, expected_num_blocks, b.NumBlocks())
  }
  for i, expected_block := range [...]string{
      "abcd", "ABCD", "qrst", "QRST", "wx"} {
    extracted := b.Block(i).ToString()
    if extracted != expected_block {
      t.Errorf(
          "%q block %d should be %q but got %q",
          b.ToString(), i, expected_block, extracted)
    }
  }
}


func TestGetBlockPadded(t *testing.T) {
  b := FromString("YELLOW SUBMARINE")
  b.SetBlockSize(20)
  padded := b.BlockPadded(0)
  expected := "YELLOW SUBMARINE\x04\x04\x04\x04"
  if padded.ToString() != expected {
    t.Errorf(
        "Padded %q should be %q but got %q.",
        b.ToString(), expected, padded.ToString())
  }
}


func TestTranspose(t *testing.T) {
  block_size := 4
  input := FromString("abcdABCDqrstQRSTwx")
  input.SetBlockSize(block_size)
  output := input.Transposed()
  if output.NumBlocks() != block_size {
    t.Errorf(
        "transposition should have %d blocks, reports %d.",
        block_size, output.NumBlocks())
  }
  for i, expected_block := range [...]string{
      "aAqQw", "bBrRx", "cCsS\x00", "dDtT\x00"} {
    extracted := output.Block(i).ToString()
    if extracted != expected_block {
      t.Errorf(
          "%q block %d should be %q but got %q",
          output.ToString(), i, expected_block, extracted)
    }
  }
}


func TestSlice(t *testing.T) {
  input := FromString("yellow submarineYELLOW SUBMARINEyellow submarine")
  expected_sliced := FromString("marineYELLOW SUBMARINEyellow submarine")
  sliced := input.Slice(10)
  if expected_sliced.ToString() != sliced.ToString() {
    t.Errorf(
        "Expected sliced to be %q but got %q.",
        expected_sliced.ToString(), sliced.ToString())
  }
}
