from Crypto.Cipher import AES
import hashlib

def encrypt_AES_GCM(msg, secretKey):
    # create cipher
    aesCipher = AES.new(secretKey, AES.MODE_GCM)

    # encrypt and digest
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)

    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    # create cipher
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)

    # decrypt and verify
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)

    return plaintext

def ecc_point_to_256_bit_key(point):
    # hash the x and y coordinates of the ECC public key to get desired AES key length
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))

    return sha.digest()