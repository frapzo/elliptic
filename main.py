from tinyec import registry
import secrets
from ecc import encrypt_ECC, decrypt_ECC

MESSAGE = b'Hello, World!'

curve = registry.get_curve('secp256r1')

mailbox = {}

# generate private keys for Alice and Bob
alicePrivKey = secrets.randbelow(curve.field.n)
bobPrivKey = secrets.randbelow(curve.field.n)

def prepare_keys():
    # generate public keys for Alice and Bob
    alicePubKey = alicePrivKey * curve.g
    bobPubKey = bobPrivKey * curve.g

    # store public keys in mailbox (central authority)
    mailbox['alice'] = alicePubKey
    mailbox['bob'] = bobPubKey

def alice_send_message():
    # Encrypt message with public key
    public_key = mailbox['bob']
    encryptedMsg = encrypt_ECC(MESSAGE, public_key)
    mailbox['encryptedMsg'] = encryptedMsg

    return encryptedMsg

def bob_receive_message():
    # Decrypt message with private key
    encryptedMsg = mailbox.pop('encryptedMsg')
    decryptedMsg = decrypt_ECC(encryptedMsg, bobPrivKey)
    print(f"Decrypted message: {decryptedMsg.decode('utf-8')}")

if __name__ == "__main__":
    prepare_keys()
    alice_send_message()
    bob_receive_message()