from Crypto.Cipher import AES

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