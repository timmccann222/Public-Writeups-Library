from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def decrypt_string(encrypted_string, key):
    # Base64 decode the encrypted string
    encrypted_bytes = base64.b64decode(encrypted_string)
    
    # Set up AES decryption parameters
    iv = b"1tdyjCbY1Ix49842"
    key_bytes = key.encode('utf-8')
    
    # Ensure the key length is 16 bytes (128 bits)
    if len(key_bytes) != 16:
        raise ValueError("Key must be 16 bytes long")
    
    # Create the AES cipher in CBC mode
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.CBC(iv),
        backend=default_backend()
    )
    
    decryptor = cipher.decryptor()
    
    # Decrypt the data
    decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    # Remove PKCS7 padding
    pad_len = decrypted_padded[-1]
    decrypted_data = decrypted_padded[:-pad_len]

    return decrypted_data.decode('utf-8')

# Encrypted string and key
encrypted_string = "BQO5l5Kj9MdErXx6Q6AGOw=="
key = "c4scadek3y654321"

# Decrypt the string
try:
    decrypted_string = decrypt_string(encrypted_string, key)
    print("Decrypted string:", decrypted_string)
except Exception as e:
    print("Error:", e)
