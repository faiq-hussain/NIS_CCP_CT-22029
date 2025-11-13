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
        decrypted_char_ord = (mod_inv_a * (y - b)) % 26
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
    """Naive frequency-map attack (still quite limited for combined cipher)."""
    english_freq_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    cipher_counts = Counter(ciphertext)
    cipher_sorted = [pair[0] for pair in cipher_counts.most_common()]
    mapping = {cipher_sorted[i]: english_freq_order[i] for i in range(min(len(cipher_sorted), 26))}
    guessed_plaintext = ''.join(mapping.get(c, c) for c in ciphertext)
    return guessed_plaintext, mapping

def known_plaintext_attack(known_plain, known_cipher, full_cipher, a=None, b=None, try_bruteforce_affine=False):
    """
    Improved known-plaintext attack.

    - If a and b are provided, the function assumes `known_plain` is the ORIGINAL plaintext (pre-affine),
      so it first computes the affine output for that segment, then deduces Vigenere key shifts.
    - If a and b are None, the function assumes `known_plain` is the AFFINE-output (post-affine) already.
    - If try_bruteforce_affine=True and a,b are None, the function will brute force all valid affine (a,b)
      possibilities and return candidate keys/decryptions (may produce many candidates).
    Returns:
      - a dictionary with keys:
        'affine_used': (a,b) or None
        'recovered_key_fragment': key fragment (as letters)
        'full_decryption_with_fragment': result of decrypting full_cipher using fragment repeated
        'candidates' (only for brute force) : list of candidate dicts
    """
    known_plain = format_string(known_plain)
    known_cipher = format_string(known_cipher)
    full_cipher = format_string(full_cipher)

    results = {
        'affine_used': None,
        'recovered_key_fragment': None,
        'full_decryption_with_fragment': None,
        'candidates': []
    }

    def derive_key_from_affine_segment(known_affine_seg, known_final_seg):
        if len(known_affine_seg) != len(known_final_seg):
            raise ValueError("Known affine segment and known final segment must be same length.")
        key_chars = []
        for p, c in zip(known_affine_seg, known_final_seg):
            p_val = ord(p) - ord('A')
            c_val = ord(c) - ord('A')
            shift = (c_val - p_val) % 26
            key_chars.append(chr(shift + ord('A')))
        return ''.join(key_chars)

    valid_a_values = [x for x in range(1, 26) if mod_inverse(x, 26) is not None]

    if a is not None and b is not None:
        known_affine = affine_encrypt(known_plain, a, b)
        recovered_fragment = derive_key_from_affine_segment(known_affine, known_cipher)
        results['affine_used'] = (a, b)
        results['recovered_key_fragment'] = recovered_fragment
        candidate_key = recovered_fragment
        decrypted_with_candidate = vigenere_decrypt(full_cipher, candidate_key)
        results['full_decryption_with_fragment'] = decrypted_with_candidate
        return results

    if try_bruteforce_affine:
        for a_try in valid_a_values:
            for b_try in range(26):
                known_affine = affine_encrypt(known_plain, a_try, b_try)
                recovered_fragment = derive_key_from_affine_segment(known_affine, known_cipher)
                candidate_key = recovered_fragment
                decrypted_with_candidate = vigenere_decrypt(full_cipher, candidate_key)
                results['candidates'].append({
                    'affine': (a_try, b_try),
                    'recovered_fragment': recovered_fragment,
                    'decrypted_with_fragment': decrypted_with_candidate
                })
        return results

    recovered_fragment = derive_key_from_affine_segment(known_plain, known_cipher)
    results['recovered_key_fragment'] = recovered_fragment
    results['full_decryption_with_fragment'] = vigenere_decrypt(full_cipher, recovered_fragment)
    return results

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

    print("\n--- Frequency Analysis Attack (naive) ---")
    freq_guess, freq_map = frequency_analysis_attack(encrypted)
    print(f"Guessed Text: {freq_guess}")
    print(f"Letter Mapping: {freq_map}")

    print("\n--- Known Plaintext Attack ---")
    print("Provide the ORIGINAL plaintext segment (not the intermediate/affine output).")
    known_plain = input("Enter known portion of ORIGINAL plaintext: ")
    known_cipher = input("Enter corresponding portion of FINAL ciphertext: ")

   
    kp_result = known_plaintext_attack(known_plain, known_cipher, encrypted, a=AFFINE_KEY_A, b=AFFINE_KEY_B)
    print(f"\nRecovered Vigenère key fragment (using affine a={AFFINE_KEY_A}, b={AFFINE_KEY_B}): {kp_result['recovered_key_fragment']}")
    print("Possible decryption of full ciphertext using this fragment (fragment repeated):")
    print(kp_result['full_decryption_with_fragment'])

   