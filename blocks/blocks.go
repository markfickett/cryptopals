/**
 * Blocks of bytes, with hex and Base64 encoding/decoding.
 * https://cryptopals.com/sets/1/challenges/1
 */

package blocks

import "encoding/base64"
import "bytes"
import "fmt"

type blocks struct {
  block_size int
  buf bytes.Buffer
}

func NewBlocks() *blocks {
  return &blocks{block_size: 16}
}

func FromBytes(input_buf []byte) *blocks {
  return &blocks{block_size: 16, buf: *bytes.NewBuffer(input_buf)}
}

func FromBytesBuffer(input_buf bytes.Buffer) *blocks {
  return &blocks{block_size: 16, buf: input_buf}
}

func Equal(a *blocks, b *blocks) bool {
  return bytes.Equal(a.buf.Bytes(), b.buf.Bytes())
}

func FromHex(encoded_hex string) *blocks {
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

func (b* blocks) ToHex() string {
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

func (b *blocks) ToBase64() string {
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

func FromBase64(encoded string) *blocks {
  data, err := base64.StdEncoding.DecodeString(encoded)
  if err != nil {
    panic(err)
  }
  return FromBytes(data)
}