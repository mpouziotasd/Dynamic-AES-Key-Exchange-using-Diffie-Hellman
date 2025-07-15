import os
import random

from src.colors import colors

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Crypto.Cipher import AES

from Crypto.Util.number import getPrime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key_DH(shared_secret, key_len: int = 32):
    """
        Generates a key using AES (Advanced Encryption System) with Defie Hellman key exchange
        and encrypts data using SHA256.
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=None,
        info=b'handshake data',
    )
    return kdf.derive(shared_secret)


# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def authenticate_signature(public_key, signed_data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

# Generate Keys using Diffie-Hellman
def generate_keys(prime, generator):
    private_key = random.randint(2, prime - 2)
    public_key = pow(generator, private_key, prime)

    return private_key, public_key

def calculate_shared_secret(prime, priv_key, pub_key):
    return pow(pub_key, priv_key, prime)

def int_to_bytes(x, length):
    return x.to_bytes((x.bit_length() + 7)//8, byteorder='big')

def main():
    prime = getPrime(2048)
    generator = 2
    nonce = os.urandom(16)
    
    # Generate Alice's and Bob's keys
    alice_prvt_key, alice_pub_key = generate_keys(prime, generator)
    bob_prvt_key, bob_pub_key = generate_keys(prime, generator)

    # Generate RSA key pairs
    alice_rsa_priv, alice_rsa_pub = generate_rsa_keys()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keys()

    alice_shared_secret = calculate_shared_secret(prime, alice_prvt_key, bob_pub_key)
    bob_shared_secret = calculate_shared_secret(prime, bob_prvt_key, alice_pub_key)

    if not alice_shared_secret == bob_shared_secret:
        print(colors.FAIL + "Shared secret does not match...\n Shutting down communication" + colors.ENDC)
        exit(-1)

    AES_key = derive_key_DH(int_to_bytes(alice_shared_secret, 256), 32)  # AES-256 key length

    alice_signed_data = alice_rsa_priv.sign(AES_key, padding.PKCS1v15(), hashes.SHA256())
    
    print("\nBob's Side:")
    # Bob's Side
    if authenticate_signature(alice_rsa_pub, AES_key, alice_signed_data):
        print(colors.GREEN + "Bob verified Alice's signed data successfully!" + colors.ENDC)    
        plaintext = b"Hello Alice, this is Bob. Let's communicate securely!"
        cipher = AES.new(AES_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, _ = cipher.encrypt_and_digest(plaintext)
        print(colors.CYAN + "Bob signed ciphertext and sending to Alice..." + colors.ENDC)
        bob_signed_ciphertext = bob_rsa_priv.sign(ciphertext, padding.PKCS1v15(), hashes.SHA256())
        
    else:
        print(colors.FAIL + "Signature verification failed!" + colors.ENDC)
        exit(-1)
    
    print("\nAlice's Side:")
    # Alice's Side
    if authenticate_signature(bob_rsa_pub, ciphertext, bob_signed_ciphertext):
        print(colors.GREEN + "Alice verified Bob's signed data successfully!\nCommunication is Secure..." + colors.ENDC)
        print(colors.CYAN + "Decrypting Bob's message..." + colors.ENDC)
        cipher = AES.new(AES_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        print("Decrypted data:", decrypted_data)
    else:
        print(colors.FAIL + "Bob's signature verification failed!" + colors.ENDC)
        exit(-1)

if __name__ == "__main__":
    print("Establishing secure communication between Alice and Bob...")
    main()