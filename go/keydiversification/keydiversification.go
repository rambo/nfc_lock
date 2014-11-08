/**
 * This package implements symmetric key diversification as decribed in
 * NXP Application Note AN10922
 *
 * Currently implements only AES128
 */
package keydiversification;

import (
    "github.com/jacobsa/crypto/cmac"
)

/**
 * AES128 CMAC based diversification
 *
 * @param []byte key The master key to diversify
 * @param []byte aid Application id (as bytearray), PONDER: take uint32_t instead ??
 * @param []byte uid Card UID
 * @param []byte systemid The "System ID" this can be anything as long as it's constant and not too long
 * @return ([]byte, error) The new key and error if any
 */
func AES128(key []byte, aid []byte, uid []byte, systemid []byte) ([]byte, error) {

    message := make([]byte, len(uid)+len(aid)+len(systemid)+1)
    message[0] =0x01
    copy(message[1:], uid)
    copy(message[len(uid)+1:], aid)
    copy(message[len(uid)+len(aid)+1:], systemid)

    mac, err := cmac.New(key)
    if err != nil {
        return message, err
    }

    // This always succeeds
    mac.Write(message)

    // Extract the key
    message_et_cmac := mac.Sum(message)
    new_key := message_et_cmac[len(message):]

    return new_key, nil;
}
