package xor_crypt

import "fmt"
import "strings"
import "testing"

import "../blocks"

func TestDecryptSingleByteXor(t *testing.T) {
  cipher_text := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e" +
      "783a393b3736"
  _, _, clear_text := XorDecrypt(blocks.FromHex(cipher_text))
  expected_word := "bacon"
  if !strings.Contains(clear_text, expected_word) {
    t.Error(fmt.Sprintf(
        "Sample text should have %q in it, but decrypted as %q.",
        expected_word, clear_text))
  }
}


func TestDecryptSingleByteXorPunctuation(t *testing.T) {
  cipher_text := "1a531a5f7e495f4e30305f4e4e561a4f435c1a30565b4e5b5b1a1a5f715" +
      "6555b1a1a1a4e1d554e1a4f551a575d5b5f53434f4a531a551d1a554d495b5f1d4f165" +
      "45e5b1a1a5f5b541a5f545e491a541a54521a1a53521a521a541a521a4f534f431a5600"
  cipher_text_blocks := blocks.FromHex(cipher_text)
  _, key, clear_text := XorDecrypt(cipher_text_blocks)
  expected_key := byte(':')
  if key != expected_key {
    t.Error(fmt.Sprintf(
        "Key should be %s/0x%x (cleartext %q) but got %s/0x%x (cleartext %q)",
        string(expected_key),
        expected_key,
        cipher_text_blocks.Xor(blocks.FromByte(expected_key)).ToString(),
        string(key),
        key,
        clear_text))
  }
}


func TestScore(t *testing.T) {
  non_english := "iU\x1chkZHXPIK\x16tXKAnQWs\x1bAD>XtbxIK"
  bad_score := GetScore(non_english)
  english := "Now that the party is jumping\n"
  good_score := GetScore(english)
  if bad_score >= good_score {
    t.Error(fmt.Sprintf(
        "bad %q scored %d >= good %q which scored %d",
        bad_score, non_english, good_score, english))
  }
}


func TestEncrypt(t *testing.T) {
  clear_text :=
      "Burning 'em, if you ain't quick and nimble\n" +
      "I go crazy when I hear a cymbal"
  expected_hex :=
      "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727" +
      "65272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028316528632630" +
      "2e27282f"
  key := "ICE"
  cipher_text := blocks.FromString(clear_text).Xor(blocks.FromString(key))
  cipher_hex := cipher_text.ToHex()
  if cipher_hex != expected_hex {
    t.Error(fmt.Sprintf(
        "%q ^ %q encrypted as %q, should be %q",
        key, clear_text, cipher_hex, expected_hex))
  }
}


func TestFindKeySize(t *testing.T) {
  clear_text := blocks.FromString(
      "The moving finger writes, and having writ, moves on --\n" +
      "nor all your piety, nor wit, wash out a word of it,\n" +
      "nor all your tears wash out a word of it.")

  key := blocks.FromString("KAYaM")
  cipher_text := clear_text.Xor(key)
  key_size := FindKeySize(cipher_text)
  if key_size != key.Len() {
    t.Error(fmt.Sprintf(
        "Expected key size %d but got %d.", key.Len(), key_size))
  }
}
