AFFINE_KEY_A = 7
AFFINE_KEY_B = 10
VIGENERE_KEY = "CRYPTOGRAPHY" 

def format_string(text):
    return "".join(filter(str.isalpha, text)).upper()

def mod_inverse(a, m):
    """Finds the modular multiplicative inverse of a under modulo m."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None 

def affine_encrypt(plaintext, a, b):
    """Encrypts text using the Affine cipher E(x) = (ax + b) % 26."""
    ciphertext = ""
    for char in plaintext:
        x = ord(char) - ord('A')
        encrypted_char_ord = (a * x + b) % 26
        ciphertext += chr(encrypted_char_ord + ord('A'))
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    """Decrypts text from the Affine cipher."""
    plaintext = ""
    mod_inv_a = mod_inverse(a, 26)
    if mod_inv_a is None:
        raise ValueError("'a' key has no modular inverse. Cannot decrypt.")
    
    for char in ciphertext:
        y = ord(char) - ord('A')
        decrypted_char_ord = (mod_inv_a * (y - b + 26)) % 26
        plaintext += chr(decrypted_char_ord + ord('A'))
    return plaintext

def vigenere_encrypt(plaintext, key):
    """Encrypts text using the Vigenère cipher."""
    encrypted_text = ""
    key_index = 0
    for char in plaintext:
        key_shift = ord(key[key_index % len(key)]) - ord('A')
        encrypted_char_ord = (ord(char) - ord('A') + key_shift) % 26
        encrypted_text += chr(encrypted_char_ord + ord('A'))
        key_index += 1
    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    """Decrypts text from the Vigenère cipher."""
    decrypted_text = ""
    key_index = 0
    for char in ciphertext:
        key_shift = ord(key[key_index % len(key)]) - ord('A')
        decrypted_char_ord = (ord(char) - ord('A') - key_shift + 26) % 26
        decrypted_text += chr(decrypted_char_ord + ord('A'))
        key_index += 1
    return decrypted_text

def custom_cipher_encrypt(plaintext, a, b, v_key):
    """Encrypts with Affine then Vigenère."""
    formatted_plaintext = format_string(plaintext)
    affine_ciphertext = affine_encrypt(formatted_plaintext, a, b)
    final_ciphertext = vigenere_encrypt(affine_ciphertext, v_key)
    return final_ciphertext

def custom_cipher_decrypt(ciphertext, a, b, v_key):
    """Decrypts from Vigenère then Affine."""
    vigenere_plaintext = vigenere_decrypt(ciphertext, v_key)
    final_plaintext = affine_decrypt(vigenere_plaintext, a, b)
    return final_plaintext

# --- Example Usage ---
# --- Example Usage ---
message = "We will attack in Dawn"
formatted_message = format_string(message)

intermediateCipher = affine_encrypt(formatted_message, AFFINE_KEY_A, AFFINE_KEY_B)
encrypted = custom_cipher_encrypt(message, AFFINE_KEY_A, AFFINE_KEY_B, VIGENERE_KEY)
intermediateDeCipher = vigenere_decrypt(encrypted, VIGENERE_KEY)
decrypted = custom_cipher_decrypt(encrypted, AFFINE_KEY_A, AFFINE_KEY_B, VIGENERE_KEY)

print(f"Original:              {formatted_message}")
print(f"Intermediate Cipher:   {intermediateCipher}")
print(f"Final Cipher:          {encrypted}")
print(f"Intermediate DeCipher: {intermediateDeCipher}")
print(f"Decrypted:             {decrypted}")


