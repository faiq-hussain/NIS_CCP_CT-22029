from collections import Counter
import math
import random

ENGLISH_FREQ = {
 'A': 0.08167,'B': 0.01492,'C': 0.02782,'D': 0.04253,'E': 0.12702,'F': 0.02228,'G': 0.02015,
 'H': 0.06094,'I': 0.06966,'J': 0.00153,'K': 0.00772,'L': 0.04025,'M': 0.02406,'N': 0.06749,
 'O': 0.07507,'P': 0.01929,'Q': 0.00095,'R': 0.05987,'S': 0.06327,'T': 0.09056,'U': 0.02758,
 'V': 0.00978,'W': 0.02360,'X': 0.00150,'Y': 0.01974,'Z': 0.00074
}

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def format_string(text):
    return "".join(ch for ch in text.upper() if ch.isalpha())

def mod_inverse(a, m=26):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt_plaintext(plain_upper, a, b):
    out = []
    for ch in plain_upper:
        x = ord(ch) - 65
        out.append(chr(((a * x + b) % 26) + 65))
    return "".join(out)

def affine_decrypt_text(cipher_upper, a, b):
    inv = mod_inverse(a, 26)
    if inv is None:
        raise ValueError("'a' has no inverse mod 26")
    out = []
    for ch in cipher_upper:
        y = ord(ch) - 65
        out.append(chr(((inv * (y - b + 26)) % 26) + 65))
    return "".join(out)

def vigenere_encrypt_text(plain_upper, key_upper):
    out = []
    k = key_upper
    for i,ch in enumerate(plain_upper):
        shift = ord(k[i % len(k)]) - 65
        out.append(chr(((ord(ch)-65 + shift) % 26) + 65))
    return "".join(out)

def vigenere_decrypt_text(cipher_upper, key_upper):
    out = []
    k = key_upper
    for i,ch in enumerate(cipher_upper):
        shift = ord(k[i % len(k)]) - 65
        out.append(chr(((ord(ch)-65 - shift + 26) % 26) + 65))
    return "".join(out)

def hybrid_encrypt(plaintext, a, b, vkey):
    f = format_string(plaintext)
    aff = affine_encrypt_plaintext(f, a, b)
    return vigenere_encrypt_text(aff, vkey.upper())

def letter_freq(text):
    c = Counter(text)
    return {ch: c.get(ch, 0) for ch in ALPH}, sum(c.values())

def index_of_coincidence(text):
    freqs, N = letter_freq(text)
    if N <= 1:
        return 0.0
    s = sum(v*(v-1) for v in freqs.values())
    return s / (N*(N-1))

def avg_column_ic_for_length(cipher_upper, L):
    cols = ['' for _ in range(L)]
    for i,ch in enumerate(cipher_upper):
        cols[i % L] += ch
    ics = [index_of_coincidence(col) for col in cols if len(col) > 0]
    return sum(ics)/len(ics) if ics else 0.0

def find_key_length_by_ic(cipher_upper, max_len=20):
    best_L = 1
    best_score = -1
    scores = {}
    for L in range(1, min(max_len, len(cipher_upper)) + 1):
        avg_ic = avg_column_ic_for_length(cipher_upper, L)
        scores[L] = avg_ic
        if avg_ic > best_score:
            best_score = avg_ic
            best_L = L
    return best_L, scores

def chi_squared_score(obs_counts, expected_counts):
    score = 0.0
    for ch in ALPH:
        o = obs_counts.get(ch, 0)
        e = expected_counts.get(ch, 0)
        if e > 0:
            score += ((o - e)**2) / e
    return score

def guess_vigenere_key_for_length(cipher_upper, L):
    cols = ['' for _ in range(L)]
    for i,ch in enumerate(cipher_upper):
        cols[i % L] += ch
    key_letters = []
    for col in cols:
        if len(col) == 0:
            key_letters.append('A')
            continue
        best_shift = 0
        best_score = float('inf')
        for shift in range(26):
            # decrypt this column with shift -> treat as Caesar-decoded column
            dec = ''.join(chr(((ord(c)-65 - shift) % 26) + 65) for c in col)
            counts = Counter(dec)
            expected = {ch: ENGLISH_FREQ[ch] * len(dec) for ch in ALPH}
            score = chi_squared_score(counts, expected)
            if score < best_score:
                best_score = score
                best_shift = shift
        key_letters.append(chr(best_shift + 65))
    return ''.join(key_letters)

def solve_affine_from_top2(freqed_intermediate):
    most_common = freqed_intermediate.most_common()
    if len(most_common) < 2:
        return None
    (y1, _), (y2, _) = most_common[0], most_common[1]
    y1_idx = ord(y1) - 65
    y2_idx = ord(y2) - 65
    res = []
    for (p1_idx, p2_idx) in [(4,19),(19,4)]:  
        lhs = (p1_idx - p2_idx) % 26
        rhs = (y1_idx - y2_idx) % 26
        inv = mod_inverse(lhs, 26)
        if inv is None:
            continue
        a = (rhs * inv) % 26
        b = (y1_idx - a * p1_idx) % 26
        
        if math.gcd(a, 26) != 1:
            continue
        res.append((a, b, (p1_idx,p2_idx)))
    return res  

def two_stage_attack(ciphertext, max_keylen=20):
    c = ciphertext.upper()
    guessed_L, scores = find_key_length_by_ic(c, max_len=max_keylen)
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_L_candidates = [L for L,_ in sorted_scores[:5]]
    stage1_results = {"guessed_L": guessed_L, "scores": scores, "top_Ls": top_L_candidates}
    stage2_results = []
    for L in top_L_candidates:
        guessed_k = guess_vigenere_key_for_length(c, L)
        intermediate = vigenere_decrypt_text(c, guessed_k)
        freq = Counter(intermediate)
        cand_ab = solve_affine_from_top2(freq)
        if not cand_ab:
            stage2_results.append({"L":L, "guessed_k":guessed_k, "candidates_ab":[], "recovered_plain":None})
            continue
        successes = []
        for (a,b, mapping) in cand_ab:
            try:
                plain_candidate = affine_decrypt_text(intermediate, a, b)
            except Exception:
                continue
            successes.append({"a":a, "b":b, "mapping":mapping, "plaintext": plain_candidate})
        stage2_results.append({"L":L, "guessed_k":guessed_k, "candidates_ab":successes})
    return stage1_results, stage2_results

def simulate_attack_over_lengths(A_affine, B_affine, VKEY, long_plain_base, lengths=[400,2000,5000]):
    results = {}
    needed_len = max(lengths) + 100
    repeated = (long_plain_base + " ") * ((needed_len // len(long_plain_base)) + 3)
    repeated = format_string(repeated)[:needed_len]
    for L in lengths:
        sample_plain = repeated[:L]
        cipher = vigenere_encrypt_text(affine_encrypt_plaintext(sample_plain, A_affine, B_affine), VKEY.upper())
        s1, s2 = two_stage_attack(cipher, max_keylen=30)
        success = False
        recovered_details = []
        for res in s2 == s2 if False else s2:  
            pass
        _, stage2_results = s1, s2  
def run_simulation_demo():
  
    A = 7
    B = 10
    V = "CRYPTOGRAPHY"
    base = ("In the event of war the quick brown fox jumps over the lazy dog. "
            "The rain in Spain stays mainly in the plain. Attack at dawn was expected. "
            "This is sample text used to build up text length for statistical analysis. ")
    lengths = [400, 2000, 5000]
    print("Simulation with affine a,b =", (A,B), "and Vigenere key:", V)
    needed = max(lengths) + 200
    repeated = (base * ((needed // len(base)) + 3))[:needed]
    repeated = format_string(repeated)
    for L in lengths:
        plain = repeated[:L]
        cipher = vigenere_encrypt_text(affine_encrypt_plaintext(plain, A, B), V)
        s1, s2 = two_stage_attack(cipher, max_keylen=30)
        print("\n=== LENGTH:", L, "chars ===")
        print("Stage1 guessed L (best by avg IC):", s1["guessed_L"])
        print("Top L candidates by avg column IC (top 5):", s1["top_Ls"])
        for entry in s2:
            print("\nAttempt L =", entry["L"])
            print("Guessed Vigenere key:", entry["guessed_k"])
            if not entry["candidates_ab"]:
                print("  No affine (a,b) candidates found for this guessed key.")
            else:
                for cand in entry["candidates_ab"]:
                    a,c_b = cand["a"], cand["b"]
                    recovered_plain = cand["plaintext"]
                    match_keys = (a == A and c_b == B)
                    print(f"  Candidate a={a} b={c_b} mapping={cand['mapping']}  match_affine={match_keys}")
                    if recovered_plain[:50] == plain[:50]:
                        print("    -> first 50 letters match original plaintext (good sign)")
                    for w in ["ATTACK","DAWN","THE","AND","WILL"]:
                        if w in recovered_plain:
                            print("    contains word:", w)
        success_overall = False
        for entry in s2:
            if entry["guessed_k"].upper() == V.upper():
                for cand in entry["candidates_ab"]:
                    if cand["a"] == A and cand["b"] == B:
                        success_overall = True
        print("Overall attack success (found exact keys):", success_overall)

if __name__ == "__main__":
    run_simulation_demo()
