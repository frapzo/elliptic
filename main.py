from tinyec import registry
from tinyec.ec import Point
import secrets
from ecc import encrypt_ECC, decrypt_ECC

MESSAGE = b'Hello, World!'

curve = registry.get_curve('secp256r1')

CA = {}

# open channel to send messages 
mailbox = []

# Bob has a private key
bobPrivKey: int = secrets.randbelow(curve.field.n)
alicePrivKey: int = secrets.randbelow(curve.field.n)
sharedKey: Point = None

def prepare_CA() -> None:
    # Calculate public keys
    alicePubKey = alicePrivKey * curve.g
    bobPubKey = bobPrivKey * curve.g

    # store public keys in CA
    CA['alice'] = alicePubKey
    CA['bob'] = bobPubKey

def alice_ecdf() -> Point:
    # Alice generates a new key for the communication
    cipherPrivKey = secrets.randbelow(curve.field.n)
    cipherPubKey = cipherPrivKey * curve.g

    # Alice uses Bob's public key to calculate shared key
    aliceSharedKey = cipherPrivKey * CA['bob'] # sharedKey = cipherPrivKey * (bobPrivKey * curve.g)

    # Alice send the cipher public key to Bob
    mailbox.append(cipherPubKey)

    return aliceSharedKey

def bob_ecdf() -> Point:
    # Bob uses cipher public key to calculate shared key
    cipherPubKey = mailbox.pop(0)
    bobSharedKey = bobPrivKey * cipherPubKey # sharedKey = bobPrivKey * (cipherPrivKey * curve.g)

    return bobSharedKey

def ECDF() -> None:
    """Elliptic Curve Diffie-Hellman"""
    global sharedKey

    aliceSharedKey = alice_ecdf()

    bobSharedKey = bob_ecdf()

    # verify that shared keys are equal
    assert aliceSharedKey == bobSharedKey

    # set shared key as both have calculated it
    sharedKey = aliceSharedKey

def alice_send_message() -> None:
    # Encrypt message with shared key
    encryptedMsg = encrypt_ECC(MESSAGE, sharedKey)
    mailbox.append(encryptedMsg)

def bob_receive_message() -> None:
    # Decrypt message with private key
    encryptedMsg = mailbox.pop(0)
    decryptedMsg = decrypt_ECC(encryptedMsg, sharedKey).decode('utf-8')
    print(f"Decrypted message: {decryptedMsg}")

if __name__ == "__main__":
    prepare_CA()
    ECDF()
    alice_send_message()
    bob_receive_message()