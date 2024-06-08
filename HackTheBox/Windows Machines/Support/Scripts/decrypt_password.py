import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

def decrypt_password(enc_password, key):
    key_bytes = key.encode('latin1')  # Convert key to bytes using 'latin1' encoding
    array = base64.b64decode(enc_password)
    array2 = bytearray(array)  # Mutable copy of array
    key_length = len(key_bytes)
    
    for i in range(len(array)):
        array2[i] = array[i] ^ key_bytes[i % key_length] ^ 223
    
    return array2.decode('latin1')  # Using 'latin1' to match .NET's Encoding.Default

decrypted_password = decrypt_password(enc_password, key)
print(decrypted_password)
