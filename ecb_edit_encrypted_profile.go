/**
 * Given an encryption oracle for url-encoded profiles, edit an encrypted
 * profile. (Cut-and-paste attack.)
 * https://cryptopals.com/sets/2/challenges/13
 */

package main

import (
  "crypto/aes"
  "log"
  "net/url"
  "strconv"

  "./blocks"
  "./aes_modes"
)


/** Simple user profile which can be URL-encoded. */
type Profile struct {
  email string
  uid int64
  role string  // admin|user, the field the attack will target
}


func NewProfile(email string) *Profile {
  return &Profile{email: email, uid: 10, role: "user"}
}


func (p *Profile) Encode() string {
  values := url.Values{}
  values.Set("email", p.email)
  values.Set("uid", strconv.FormatInt(p.uid, 10))
  values.Set("role", p.role)
  // Add a tailing sentinel to avoid issues with ECB padding
  values.Set("zsentinel", "x")
  return values.Encode()
}


func DecodeProfile(encoded string) *Profile {
  values, err := url.ParseQuery(encoded)
  if err != nil {
    log.Fatal(err)
  }
  uid, err := strconv.Atoi(values.Get("uid"))
  if err != nil {
    log.Fatal(err)
  }
  return &Profile{
      email: values.Get("email"),
      uid: int64(uid),
      role: values.Get("role")}
}


/** ECB en/decrypter for encoded Profiles, with a consistent secret key. */
type ProfileCrypter struct {
  key *blocks.Blocks
}


func NewProfileCrypter() *ProfileCrypter {
  return &ProfileCrypter{key: blocks.RandomBlock(aes.BlockSize)}
}


/** Only this function of the crypter is available to the attacker. */
func (c *ProfileCrypter) EncryptNewProfile(email string) *blocks.Blocks {
  return c.EncryptProfile(NewProfile(email))
}


func (c *ProfileCrypter) EncryptProfile(profile *Profile) *blocks.Blocks {
  return aes_modes.EcbEncrypt(blocks.FromString(profile.Encode()), c.key)
}


func (c *ProfileCrypter) DecryptProfile(encrypted *blocks.Blocks) *Profile {
  return DecodeProfile(aes_modes.EcbDecrypt(encrypted, c.key).ToString())
}


/** Using only EncryptNewProfile, edit a profile to have role="admin". */
func make_encrypted_profile_admin(
    encrypted_profile *blocks.Blocks,
    oracle *ProfileCrypter) *blocks.Blocks {
  // TODO
  return encrypted_profile
}


func main() {
  email := "regular@secure.com&role=admin"
  orig_secret_profile := NewProfile(email)

  // Verify that a naive attack on encoding doesn't work.
  encoded_secret_profile := orig_secret_profile.Encode()
  log.Printf("Encoded original profile as %q.", encoded_secret_profile)
  decoded_secret_profile := DecodeProfile(encoded_secret_profile)
  if decoded_secret_profile.email != email {
    log.Fatalf(
        "Email %q not recovered, got %q.",
        email, decoded_secret_profile.email)
  }
  if decoded_secret_profile.role != orig_secret_profile.role {
    log.Fatalf(
        "Role changed through en/decoding: was %q, now %q.",
        orig_secret_profile.role, decoded_secret_profile.role)
  }

  // Encrypt and attack the profile.
  crypter := NewProfileCrypter()
  encrypted_profile := crypter.EncryptProfile(orig_secret_profile)
  edited_encrypted_profile := make_encrypted_profile_admin(
      encrypted_profile, crypter)

  // Decrypt and evaluate the attacked profile.
  attacked_profile := crypter.DecryptProfile(edited_encrypted_profile)
  outcome_msg := "success"
  if attacked_profile.role != "admin" {
    outcome_msg = "failure"
  }
  log.Printf(
      "Edited profile: email=%q uid=%d role=%q (%s).",
      attacked_profile.email,
      attacked_profile.uid,
      attacked_profile.role,
      outcome_msg)
}
