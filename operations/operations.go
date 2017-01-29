/**
 * Operations on byte streams.
 */

package operations

import "bytes"


/**
 * XOR two byte arrays. Output is the length of the data buffer. If the key is
 * shorter, repeat the key to make the length of the data; if the key is
 * shorter, only use up to len(data) of the key.
 * https://cryptopals.com/sets/1/challenges/2
 */
func Xor(key []byte, data []byte) []byte {
  var out bytes.Buffer
  for i, data_byte := range data {
    out.WriteByte(data_byte ^ key[i % len(key)])
  }
  return out.Bytes()
}


/**
 * Offsets the starting point within a byte array used as an encryption key.
 * For example, to continue encrypting with a second block of text:
 *     key: ICEICEICEIC (no key offset)
 *    text: Hello world
 *     key: EICEICEICEI (offset % 3 = 2)
 *    text: , how are y
 */
func Offset(buf []byte, raw_offset int) []byte {
  offset := raw_offset % len(buf)
  return append(buf[offset:], buf[:offset]...)
}
