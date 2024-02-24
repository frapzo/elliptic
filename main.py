from tinyec import registry
import hashlib, binascii, secrets
from functions import encrypt_AES_GCM, decrypt_AES_GCM, ecc_point_to_256_bit_key

MESSAGE = b'Hello, World!'

curve = registry.get_curve('secp256r1')

secret_key = None

class prime256v1:
    def __init__(self) -> None:
        # also known as secp256r1 or P-256
        self.name = "prime256v1"

        # p is the prime for modulo
        self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

        # a and b are the coefficients for the elliptic curve equation
        self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
        self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

        # G is the generator point
        self.G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
        
        # n is the cardinality of the curve
        self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

        # h is the cofactor
        self.h = 0x1

def encrypt_ECC(msg, pubKey):
    # generate shared secret key
    sharedKey = secrets.randbelow(curve.field.n)

    # calculate shared ECC key
    pubSharedKey = sharedKey * pubKey # pubSharedKey = sharedKey * (privKey * curve.g)

    # generate AES key from shared ECC key
    secretKey = ecc_point_to_256_bit_key(pubSharedKey)

    # encrypt message with AES key
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)

    # obfuscate the shared key
    sharedPoint = sharedKey * curve.g

    return (ciphertext, nonce, authTag, sharedPoint)

def decrypt_ECC(encryptedMsg, privKey):
    # extract data from encrypted message
    (ciphertext, nonce, authTag, sharedPoint) = encryptedMsg

    # calculate shared ECC key
    sharedECCKey = privKey * sharedPoint # sharedECCKey = privKey * (sharedKey * curve.g)

    # generate AES key from shared ECC key
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)

    # decrypt message with AES key
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

if __name__ == "__main__":
    # Generate public and private keys
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g

    # Encrypt message with public key
    encryptedMsg = encrypt_ECC(MESSAGE, pubKey)

    # Create object to store encrypted message
    encryptedMsgObj = {
        'ciphertext': binascii.hexlify(encryptedMsg[0]),
        'nonce': binascii.hexlify(encryptedMsg[1]),
        'authTag': binascii.hexlify(encryptedMsg[2]),
        'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
    }
    print("hex(x) + hex(y) % 2:", encryptedMsgObj["ciphertextPubKey"])

    # Decrypt message with private key
    decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
    # print("decrypted msg:", decryptedMsg)