from Crypto.Cipher import AES

def encrypt_AES_GCM(msg: bytes, secretKey: bytes) -> tuple:
    """encrypt a message with a given secret key using AES in GCM mode

    Args:
        msg (bytes): message to be encrypted
        secretKey (bytes): secret key

    Returns:
        tuple: (ciphertext, nonce, authTag)
    """
    # create cipher
    aesCipher = AES.new(secretKey, AES.MODE_GCM)

    # encrypt and digest
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)

    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext: bytes, nonce, authTag: bytes, secretKey: bytes) -> bytes:
    """decrypt a message with a given secret key using AES in GCM mode

    Args:
        ciphertext (bytes): message to be decrypted
        nonce (_type_): nonce
        authTag (bytes): authentication tag
        secretKey (bytes): secret key

    Returns:
        bytes: encoded message
    """
    # create cipher
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)

    # decrypt and verify
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)

    return plaintext