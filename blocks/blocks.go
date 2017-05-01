/**
 * Blocks of bytes, with hex and Base64 encoding/decoding.
 * https://cryptopals.com/sets/1/challenges/1
 */

package blocks

import "encoding/base64"
import "bufio"
import "bytes"
import "fmt"
import "io"
import "math"
import "crypto/rand"


const default_block_size int = 16


type Blocks struct {
  block_size int
  buf bytes.Buffer
}


func New() *Blocks {
  return &Blocks{block_size: default_block_size}
}


func (b *Blocks) Copy() *Blocks {
  cp := FromBytes(b.buf.Bytes())
  cp.block_size = b.block_size
  return cp
}


func (b *Blocks) Append(other *Blocks) {
  b.buf.Write(other.buf.Bytes())
}


func (b *Blocks) Len() int {
  return b.buf.Len()
}


func (b *Blocks) Empty() bool {
  return b.buf.Len() == 0
}


func FromBytes(input_buf []byte) *Blocks {
  return &Blocks{
      block_size: default_block_size,
      buf: *bytes.NewBuffer(input_buf)}
}


func (b *Blocks) AppendBytes(buf []byte) {
  b.buf.Write(buf)
}

func (b *Blocks) AppendByte(value byte) {
  b.buf.WriteByte(value)
}


func FromByte(value byte) *Blocks {
  return FromBytes([]byte{ value })
}


func (b *Blocks) ToBytes() []byte {
  return b.buf.Bytes()
}


func FromString(str string) *Blocks {
  return FromBytes([]byte(str))
}


func (b *Blocks) ToString() string {
  return b.buf.String()
}


func FromBytesBuffer(input_buf bytes.Buffer) *Blocks {
  return &Blocks{block_size: default_block_size, buf: input_buf}
}


func RandomBlock(block_size int) *Blocks {
  buf := make([]byte, block_size)
  _, err := rand.Read(buf)
  if err != nil {
    panic(err)
  }
  block := FromBytes(buf)
  block.SetBlockSize(block_size)
  return block
}


func Equal(a *Blocks, b *Blocks) bool {
  return bytes.Equal(a.buf.Bytes(), b.buf.Bytes())
}


/**
 * XORs all the data in these Blocks using the given Blocks as a key. (The
 * key may be truncated or repeated to cover all the data.)
 *
 * Return the new Blocks that result.
 * https://cryptopals.com/sets/1/challenges/2
 */
func (b *Blocks) Xor(key *Blocks) *Blocks {
  var out bytes.Buffer
  if key.buf.Len() == 0 {
    return FromBytesBuffer(b.buf)
  }
  key_bytes := key.buf.Bytes()
  for i, data_byte := range b.buf.Bytes() {
    out.WriteByte(data_byte ^ key_bytes[i % len(key_bytes)])
  }
  return FromBytesBuffer(out)
}


/**
 * Returns the hamming distance between two Blocks (the number of differing
 * bits). It is an error to compare different-sized Blocks.
 *
 * https://cryptopals.com/sets/1/challenges/6
 */
func (b* Blocks) HammingDistance(other* Blocks) int {
  if b.buf.Len() != other.buf.Len() {
    panic("Cannot compute Hamming distance for mismatched Blocks.")
  }
  differing := 0
  b_bytes := b.buf.Bytes()
  a_bytes := other.buf.Bytes()
  for i, a_byte := range a_bytes {
    for j := byte(0x80); j > 0x0; j >>= 1 {
      if (a_byte & j) != (b_bytes[i] & j) {
        differing++
      }
    }
    //log.Printf(
    //    "%s 0x%x\t%s 0x%x\t%d",
    //    string(a_byte), a_byte, string(b_bytes[i]), b_bytes[i], differing)
  }
  return differing
}


func (b* Blocks) GetMinimumAndAverageHammingDistance() (float64, float64) {
  num_blocks := b.NumBlocks()
  min_dist := math.Inf(1)
  total_dist := float64(0)
  comparisons := 0
  for i := 0; i < num_blocks - 1; i++ {
    for j := i + 1; j < num_blocks; j++ {
      other_block := b.Block(j)
      if other_block.Len() != b.block_size {
        continue  // incomplete final block at this size
      }
      dist := float64(b.Block(i).HammingDistance(other_block)) /
          float64(b.block_size)
      total_dist += dist
      if dist < min_dist {
        min_dist = dist
      }
      comparisons++
    }
  }
  return min_dist, total_dist / float64(comparisons)
}


func FromHex(encoded_hex string) *Blocks {
  encoded_runes := []rune(encoded_hex)
  var decoded bytes.Buffer
  if len(encoded_runes) == 0 {
    FromBytesBuffer(decoded)
  }
  for low_nibble_index := (len(encoded_runes) - 1) % 2;
      low_nibble_index < len(encoded_runes);
      low_nibble_index += 2 {
    var decoded_byte byte = 0x0
    if low_nibble_index - 1 >= 0 {
      decoded_byte |= hex_char_to_byte(encoded_runes[low_nibble_index - 1]) << 4
      //fmt.Printf("%s", string(encoded_runes[low_nibble_index - 1]))
    }
    decoded_byte |= hex_char_to_byte(encoded_runes[low_nibble_index])
    //fmt.Printf(
    //    "%s => 0x%x\n", string(encoded_runes[low_nibble_index]), decoded_byte)
    decoded.WriteByte(decoded_byte)
  }
  return FromBytesBuffer(decoded)
}


func (b* Blocks) ToHex() string {
  var encoded bytes.Buffer
  for _, in_byte := range b.buf.Bytes() {
    encoded.WriteString(nibble_to_hex_string(in_byte >> 4))
    encoded.WriteString(nibble_to_hex_string(in_byte & 0xF))
  }
  return string(encoded.String())
}


func nibble_to_hex_string(value byte) string {
  if value < 10 {
    return string('0' + value)
  } else if value < 16 {
    return string('a' + (value - 10))
  } else {
    panic(fmt.Sprintf("Value 0x%x too big for hex nibble.", value))
  }
}


func hex_char_to_byte(value rune) byte {
  if value >= '0' && value <= '9' {
    return byte(value - '0')
  } else if value >= 'a' && value <= 'f' {
    return 10 + byte(value - 'a')
  } else {
    panic(fmt.Sprintf("Rune %q is invalid as hex.", value))
  }
}


func to_base64_char(value byte) string {
  i := value
  if i <= 'Z' - 'A' {
    return string('A' + i)
  }
  i -= ('Z' - 'A') + 1
  if i <= 'z' - 'a' {
    return string('a' + i)
  }
  i -= ('z' - 'a') + 1
  if i <= '9' - '0' {
    return string('0' + i)
  }
  i -= ('9' - '0') + 1
  if i == 0 {
    return "+"
  } else if i == 1 {
    return "/"
  } else {
    panic(fmt.Sprintf(
        "Bad input byte 0x%x (%d) for base64, remainder was %d.",
        value, value, i))
  }
}


func (b *Blocks) ToBase64() string {
  output_char_index := 5
  var encoded_6bits byte = 0x0
  var encoded bytes.Buffer
  for _, input_byte := range b.buf.Bytes() {
    for input_bit_index := 7; input_bit_index >= 0; input_bit_index-- {
      if input_byte & (0x1 << uint(input_bit_index)) > 0 {
        encoded_6bits |= (0x1 << uint(output_char_index))
      }
      //fmt.Printf(
      //    "0x%x@%d => 0x%x %d\n",
      //    input_byte, input_bit_index, encoded_6bits, encoded_6bits)
      if output_char_index == 0 {
        encoded.WriteString(to_base64_char(encoded_6bits))
        output_char_index = 5
        encoded_6bits = 0x0
      } else {
        output_char_index--
      }
    }
  }
  if output_char_index != 5 {
    encoded.WriteString(to_base64_char(encoded_6bits))
  }
  trailing := b.buf.Len() % 3
  if trailing > 0 {
    for i := trailing; i < 3; i++ {
      encoded.WriteString("=")
    }
  }
  return encoded.String()
}


func FromBase64(encoded string) *Blocks {
  data, err := base64.StdEncoding.DecodeString(encoded)
  if err != nil {
    panic(err)
  }
  return FromBytes(data)
}


func FromBase64Stream(input_stream io.Reader) *Blocks {
  text := New()
  scanner := bufio.NewScanner(input_stream)
  for scanner.Scan() {
    text.Append(FromBase64(scanner.Text()))
  }
  return text
}


func FromStringStream(input_stream io.Reader) *Blocks {
  text := New()
  buf := make([]byte, 16)
  n, _ := io.ReadFull(input_stream, buf)
  for n > 0 {
    text.AppendBytes(buf[:n])
    n, _ = io.ReadFull(input_stream, buf)
  }
  return text
}


func (b *Blocks) BlockSize() int {
  return b.block_size
}


func (b *Blocks) SetBlockSize(new_block_size int) {
  b.block_size = new_block_size
}


func (b *Blocks) NumBlocks() int {
  return int(math.Ceil(float64(b.buf.Len()) / float64(b.block_size)))
}


/**
 * Returns one block (by index) from this Blocks, wrapped in a new Blocks.
 * This does no padding, so the last block may be less the block_size long.
 */
func (b *Blocks) Block(i int) *Blocks {
  if i >= b.NumBlocks() {
    panic(fmt.Sprintf(
        "Cannot get block %d >= block count %d (for %d bytes).",
        i, b.NumBlocks(), b.buf.Len()))
  }
  start := b.block_size * i
  end := b.block_size * (i + 1)
  if end >= b.buf.Len() {  // go has no integer min
    end = b.buf.Len()
  }
  extracted := FromBytes(b.buf.Bytes()[start:end])
  extracted.block_size = b.block_size
  return extracted
}


/** Returns one block, padded if necessary with 0x04 (PKCS#7 padding). */
func (b *Blocks) BlockPadded(i int) *Blocks {
  extracted := b.Block(i)
  for extracted.buf.Len() < extracted.block_size {
    extracted.buf.WriteByte(0x04)
  }
  return extracted
}


/**
 * Returns a transposed copy of these Blocks. The first block of the returned
 * Blocks will have the first byte of each of the original blocks, and so on.
 *
 * If these Blocks' last block is not filled (total length is not a multiple of
 * block_size), missing data is replaced by null bytes (0x00).
 */
func (b *Blocks) Transposed() *Blocks {
  var transposed_bytes bytes.Buffer
  data_bytes := b.buf.Bytes()
  num_blocks := b.NumBlocks()
  for block_pos := 0; block_pos < b.block_size; block_pos++ {
    for block_num := 0; block_num < num_blocks; block_num++ {
      input_i := block_num * b.block_size + block_pos
      if input_i < len(data_bytes) {
        transposed_bytes.WriteByte(data_bytes[input_i])
      } else {
        transposed_bytes.WriteByte(0x0)
      }
    }
  }
  transposed_blocks := FromBytesBuffer(transposed_bytes)
  transposed_blocks.SetBlockSize(b.NumBlocks())
  return transposed_blocks
}


/**
 * Returns a copy of these Blocks, dropping start_index bytes from the start.
 */
func (b *Blocks) Slice(start_index int) *Blocks {
  sliced := FromBytes(b.ToBytes()[start_index:])
  sliced.SetBlockSize(b.BlockSize())
  return sliced
}
