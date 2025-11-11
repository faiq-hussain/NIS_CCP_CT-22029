import string
from collections import Counter

AFFINE_KEY_A = 7
AFFINE_KEY_B = 10
VIGENERE_KEY = "CRYPTOGRAPHY"

def format_string(text):
    return "".join(filter(str.isalpha, text)).upper()

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt(plaintext, a, b):
    ciphertext = ""
    for char in plaintext:
        x = ord(char) - ord('A')
        encrypted_char_ord = (a * x + b) % 26
        ciphertext += chr(encrypted_char_ord + ord('A'))
    return ciphertext

def affine_decrypt(ciphertext, a, b):
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
    encrypted_text = ""
    key_index = 0
    for char in plaintext:
        key_shift = ord(key[key_index % len(key)]) - ord('A')
        encrypted_char_ord = (ord(char) - ord('A') + key_shift) % 26
        encrypted_text += chr(encrypted_char_ord + ord('A'))
        key_index += 1
    return encrypted_text

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ""
    key_index = 0
    for char in ciphertext:
        key_shift = ord(key[key_index % len(key)]) - ord('A')
        decrypted_char_ord = (ord(char) - ord('A') - key_shift + 26) % 26
        decrypted_text += chr(decrypted_char_ord + ord('A'))
        key_index += 1
    return decrypted_text

def custom_cipher_encrypt(plaintext, a, b, v_key):
    formatted_plaintext = format_string(plaintext)
    affine_ciphertext = affine_encrypt(formatted_plaintext, a, b)
    final_ciphertext = vigenere_encrypt(affine_ciphertext, v_key)
    return final_ciphertext

def custom_cipher_decrypt(ciphertext, a, b, v_key):
    vigenere_plaintext = vigenere_decrypt(ciphertext, v_key)
    final_plaintext = affine_decrypt(vigenere_plaintext, a, b)
    return final_plaintext



def frequency_analysis_attack(ciphertext):
    """Try to recover text by mapping frequency of letters to English frequency order."""
    english_freq_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    cipher_counts = Counter(ciphertext)
    cipher_sorted = [pair[0] for pair in cipher_counts.most_common()]
    mapping = {cipher_sorted[i]: english_freq_order[i] for i in range(min(len(cipher_sorted), 26))}

    guessed_plaintext = ''.join(mapping.get(c, c) for c in ciphertext)
    return guessed_plaintext, mapping


def known_plaintext_attack(known_plain, known_cipher, full_cipher):
    """Given part of plaintext and corresponding ciphertext, deduce part of Vigenère key."""
    known_plain = format_string(known_plain)
    known_cipher = format_string(known_cipher)
    key = []

    for i in range(len(known_plain)):
        p = ord(known_plain[i]) - ord('A')
        c = ord(known_cipher[i]) - ord('A')
        shift = (c - p) % 26
        key.append(chr(shift + ord('A')))

    recovered_key = ''.join(key)
    print(f"[+] Recovered partial Vigenère key: {recovered_key}")

    possible_plain = vigenere_decrypt(full_cipher, recovered_key)
    return recovered_key, possible_plain


if __name__ == "__main__":
    message = input("Enter the message to encrypt: ")
    formatted_message = format_string(message)

    intermediateCipher = affine_encrypt(formatted_message, AFFINE_KEY_A, AFFINE_KEY_B)
    encrypted = custom_cipher_encrypt(message, AFFINE_KEY_A, AFFINE_KEY_B, VIGENERE_KEY)
    intermediateDeCipher = vigenere_decrypt(encrypted, VIGENERE_KEY)
    decrypted = custom_cipher_decrypt(encrypted, AFFINE_KEY_A, AFFINE_KEY_B, VIGENERE_KEY)

    print(f"\nOriginal:              {formatted_message}")
    print(f"Intermediate Cipher:   {intermediateCipher}")
    print(f"Final Cipher:          {encrypted}")
    print(f"Intermediate DeCipher: {intermediateDeCipher}")
    print(f"Decrypted:             {decrypted}")

    print("\n--- Frequency Analysis Attack ---")
    freq_guess, freq_map = frequency_analysis_attack(encrypted)
    print(f"Guessed Text: {freq_guess}")
    print(f"Letter Mapping: {freq_map}")

    print("\n--- Known Plaintext Attack ---")
    known_plain = input("Enter known portion of plaintext: ")
    known_cipher = input("Enter corresponding ciphertext: ")
    recovered_key, possible_plain = known_plaintext_attack(known_plain, known_cipher, encrypted)
    print(f"Recovered Key: {recovered_key}")
    print(f"Possible Decryption using recovered key: {possible_plain}")
