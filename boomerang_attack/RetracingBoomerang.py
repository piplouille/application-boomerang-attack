# Laetitia Debesse, Sihem Mesnager, Mounira Msahli, 2020-2021
# Based on https://github.com/eyalr0/AES-Cryptoanalysis

import matplotlib.pyplot as plt
import numpy as np
import pickle
from collections import defaultdict

from byte_utils import bytes_from_hex
from AESUtils import Gmul, getGmulInv, SBOX, mix_col

from aes import AES, pad, unpad
from keys500 import key

def calc_key_from_diff(a, b):
    res = [[]]*256
    for k in range(256):
        diff = SBOX[a^k] ^ SBOX[b^k]
        res[diff] = res[diff] + [k]
    return res

def get_col(a, num):
    if num == 0:
        return np.array([a[0],  a[5], a[10], a[15]], dtype=np.uint8)
    raise Exception("Unsupported col num")

def mixcol_first_round(p, k, col):
    plain = get_col(p,col)
    key = get_col(k, col)
    return mix_col(plain, key)


# assume zero diff in byte 0
# we know p5 = 0, and ptag5 = 0x1
def getk5(p0, ptag0, k0, diff0_index, diff2k5):
    diff0 = SBOX[p0^k0] ^ SBOX[ptag0^k0]
    if diff0_index == 0:
        coef0 = 2
        coef1 = 3
    if diff0_index == 1:
        coef0 = 1
        coef1 = 2
    if diff0_index == 2:
        coef0 = 1
        coef1 = 1
    if diff0_index == 3:
        coef0 = 3
        coef1 = 1
    coefInv5 = getGmulInv(coef1)
    diff5 = Gmul(coefInv5, Gmul(coef0, diff0))
    return diff2k5[diff5]

def get_key_pairs(p0, ptag0, diff0_index, diff2k5):
    key_pairs = {}
    for k0 in range(256):
        k5 = getk5(p0, ptag0, k0, diff0_index, diff2k5)
        if len(k5) == 2 or len(k5) == 4:
            key_pairs[k0] = k5
        elif len(k5) != 0:
            print (k5)
            raise Exception('get_key_pairs - len of k5 is bad')
    return key_pairs

def get_mixture(x,y):
    mixx = x[:]
    mixy = y[:]

    mixx[0] = y[0]
    mixx[7] = y[7]
    mixx[10] = y[10]
    mixx[13] = y[13]

    mixy[0] = x[0]
    mixy[7] = x[7]
    mixy[10] = x[10]
    mixy[13] = x[13]

    return np.array(mixx, dtype=np.uint8), np.array(mixy, dtype=np.uint8)


def MiTM(p2, ptag2, key_pairs, k0real, key_index = 3, diff0_index = 0, col=0):
    p2col = get_col(p2, col)
    p2tagcol = get_col(ptag2, col)
    k0k5diff = defaultdict(list)
    kbytediff = defaultdict(list)
    for k0 in key_pairs.keys():
        for k5 in key_pairs[k0]:
            diff = mix_col(np.concatenate([p2col[0:2],[0,0]]), [k0, k5, 0, 0])[diff0_index]
            difftag = mix_col(np.concatenate([p2tagcol[0:2],[0,0]]), [k0, k5, 0, 0])[diff0_index]
            k0k5diff[diff^difftag].append([k0, k5])
    plain = [0] * 4
    plaintag = [0] * 4
    plain[key_index] = p2col[key_index]
    plaintag[key_index] = p2tagcol[key_index]
    key_temp = [0] * 4
    for key_byte in range(256):
        key_temp[key_index] = key_byte
        diff = mix_col(plain, key_temp)[diff0_index]
        difftag = mix_col(plaintag, key_temp)[diff0_index]
        kbytediff[diff ^ difftag].append(key_byte)
    key_triple =  defaultdict(list)
    for diff in k0k5diff.keys():
        if diff in kbytediff.keys():
            for k0, k5 in k0k5diff[diff]:
                kbyte = kbytediff[diff]
                key_triple[k0+k5*256] = key_triple[k0+k5*256] + kbyte
                if k0 == k0real and False:
                    print ('This is the real deal', k0, k5, key_triple[k0+k5*256])
    return key_triple

def get_dix(b):
    """
    b représentation d'un nombre binaire
    str
    retourne int
    """
    somme = 0
    for i in range(len(b)):
        somme += int(b[i]) * 2 ** i
    return somme

def get_bit(valeur):
    """
    valeur int en base 10
    retourne str en bits longueur 8
    """
    bits = ""
    q = -1
    i = 0
    while q != 0:
        q = valeur // 2
        r = valeur % 2
        bits = str(r) + bits
        i += 1
        valeur = q
    
    # on pad le début
    bits = (8 - len(bits)) * "0" + bits
    
    return bits

def list_to_str(l):
    # Chaque case est la représentation en base 10 d'un octet
    s = ""
    for i in range(len(l)):
        b = ""
        # on convertit en bits l[i] en chaine de texte longueur 8
        s += get_bit(l[i])
    return s

def str_to_list(s):
    s = (128 - len(s)) * "0" + s
    l = []
    for i in range(0, len(s), 8):
        # on coupe en partie de longueur 8
        valeur = get_dix(s[i:i+8])
        # on convertit les bits en entier
        l.append(valeur)
    return l

def list_to_hex(l):
    s = ""
    for i in range(len(l)):
        val_hex = hex(l[i])
        if len(val_hex) == 4:
            # si on a une valeur en hexadecimal en 2 chiffres
            s+=val_hex[2:4]
        else:
            s+="0" + val_hex[2]
    return s

def hex_to_list(s):
    l = []
    if len(s) != 32:
        s = "0" * (32 - len(s)) + s
    for i in range(0, len(s), 2):
        l.append(int(s[i:i+2], 16))
    return l

def get_plain_of_cipher_mix(pi, ptagi, aes):
    # print(pi)
    # print(list_to_hex(pi))
    ci = aes.encrypt(list_to_hex(pi))
    # [62, 196, 25, 239, 75, 229, 196, 247, 13, 243, 125, 68, 225, 35, 247, 51] avec softAESr.encrypt_r
    # 9261573de66cf3ac113e9a5d58bb6d03 ici => c'est différent
    # print(ci)
    # print(hex_to_list(ci))
    ctagi = aes.encrypt(list_to_hex(ptagi))
    c2i, c2tagi = get_mixture(hex_to_list(ci), hex_to_list(ctagi))
    p2i = aes.decrypt(list_to_hex(c2i))
    p2tagi = aes.decrypt(list_to_hex(c2tagi))
    return hex_to_list(p2i), hex_to_list(p2tagi)

def find_key(pi, ptagi, p2i10, p2tagi10, p2i15, p2tagi15, index10, index15, diff0_index, col, aes, key_pairs_vec, k0real, num_cipher_for_check):
    triple10 = MiTM(p2i10, p2tagi10, key_pairs_vec[diff0_index], k0real, 3, diff0_index)
    triple15 = MiTM(p2i15, p2tagi15, key_pairs_vec[diff0_index], k0real, 2, diff0_index)
    cipher_pair_for_check = []
    for i in range(256):
        if i == index10 or i == index15:
            continue
        pi[1] = i
        ptagi[1] = i
        p2i, p2tagi = get_plain_of_cipher_mix(pi, ptagi, aes)
        # print(p2i, p2tagi, '\n')
        cipher_pair_for_check.append([get_col(p2i,col), get_col(p2tagi, col)])
        if len(cipher_pair_for_check) >= num_cipher_for_check: ### ERREUR
            break
    calc_keys = []
    cnt = 0
    for k0k5 in triple10.keys():
        if k0k5 in triple15.keys():
            k0 = k0k5 % 256
            k5 = k0k5 // 256
            if True:
                for k10 in triple15[k0k5]:
                    for k15 in triple10[k0k5]:
                        if k0 == k0real and False:
                            print ([k0, k5, k10, k15])
                            print ([k0 ^ p_5 ^ p_5_tag, k5, k10, k15])
                        cnt += 1
                        for i in range(num_cipher_for_check):
                            p2col, p2tagcol = cipher_pair_for_check[i]
                            diff = mix_col(p2col, [k0, k5, k10, k15])[diff0_index]
                            difftag = mix_col(p2tagcol, [k0, k5, k10, k15])[diff0_index]
                            if diff != difftag:
                                break
                        if diff == difftag:
                            print ('Recovered key is', [k0, k5, k10, k15])
                            calc_keys.append([k0, k5, k10, k15])
    return calc_keys


def get_key_suggestion(cur_pair, aes, verbose, key_pairs_vec, k0real, num_cipher_for_check, col=0):
    pi = cur_pair[0][:]
    ptagi = cur_pair[1][:]
    p2i10 = None
    p2i15 = None
    for i in range(256):
        pi[1] = i
        ptagi[1] = i
        p2i, p2tagi = get_plain_of_cipher_mix(pi, ptagi, aes)
        # print(p2i, p2tagi, '\n')

        if p2tagi[10] ^ p2i[10] == 0 and p2i10 is None:
            if verbose:
                p2i1 = mixcol_first_round(p2i, keyarr,0)
                p2tagi1 = mixcol_first_round(p2tagi, keyarr, 0)
                pi1 = mixcol_first_round(pi, keyarr, 0)
                ptagi1 = mixcol_first_round(ptagi, keyarr, 0)
                print ('one round diff 10', p2i1^p2tagi1, pi1^ptagi1)
                print ('plain ', get_col(p2i, col), get_col(p2tagi, col))
            p2i10 = p2i
            p2tagi10 = p2tagi
            index10 = i

        if p2tagi[15] ^ p2i[15] == 0 and p2i15 is None:
            if verbose:
                p2i1 = mixcol_first_round(p2i, keyarr,0)
                p2tagi1 = mixcol_first_round(p2tagi, keyarr, 0)
                pi1 = mixcol_first_round(pi, keyarr, 0)
                ptagi1 = mixcol_first_round(ptagi, keyarr, 0)
                print ('one round diff 15', p2i1^p2tagi1, pi1^ptagi1)
                print ('plain ', get_col(p2i, col), get_col(p2tagi, col))
            p2i15 = p2i
            p2tagi15 = p2tagi
            index15 = i
        if (p2i10 is not None) and (p2i15 is not None):
            # print(p2i10, p2i15, '\n')
            for index in range(4):
                calc_keys = find_key(pi, ptagi, p2i10, p2tagi10, p2i15, p2tagi15, index10, index15, index, col, aes, key_pairs_vec, k0real, num_cipher_for_check) # ERREUR
                # print(calc_keys)
                if len(calc_keys) > 0:
                    return calc_keys
            return None

def init_plain_text(struct_pairs):
    """init the possible plain texts"""
    plain_text = [0] * 16

    p_5 = 0
    p_5_tag = 1
    p = plain_text[:]
    p[5] = p_5
    p_tag = plain_text[:]
    p_tag[5] = p_5_tag

    if struct_pairs:
        pairs = []
        for i in range(16):
            for j in range(16, 16+8):
                pairs.append([[i] + p[1:], [j] + p_tag[1:]])
    else:
        pairs = [[p, [val] + p_tag[1:]] for val in range(1,129)]
    # print(pairs[0][1])
    return pairs, p_5, p_5_tag

def init_diff_k5(p_5, p_5_tag):
    """#prepare possible diff to k5"""
    diff2k5 = calc_key_from_diff(p_5,p_5_tag)
    return diff2k5

def main():
    ### Init variables
    verbose = False
    # If true use a structre for the pairs (optimize the amount of data)
    struct_pairs = True
    # How many cipher pairs we use to verify we got the right pair
    num_cipher_for_check = 6
    # Number of keys we want to try
    num_keys = 500

    pairs, p_5, p_5_tag = init_plain_text(struct_pairs)

    diff2k5 = init_diff_k5(p_5, p_5_tag)

    total_run = 0
    total_key_find = 0
    total_key_find_good = 0
    pair_found = []

    ### Main algo
    for key_index in range(num_keys):
        # Init round
        print("clef no : ", key_index, "\n")
        keyarr = bytes_from_hex(key[key_index])

        k5 = keyarr[5]
        k0real = keyarr[0]
        k15 = keyarr[15]
        k10 = keyarr[10]
        key_pairs_vec = [[]]*4
        print ('\nreal key number', key_index, [k0real, k5, k10, k15], "\n")
        
        aes = AES(key[key_index], 256, 5)

        ### Try attack using each pair of plain text
        for pair_index in range(len(pairs)):
            # Get the pair
            cur_pair = pairs[pair_index]
            # print("     paire no : ", pair_index, cur_pair, "\n")
            p0 = cur_pair[0][0]
            ptag0 = cur_pair[1][0]

            #negligble pre process work to generate 4 possible k0 k5 pairs
            for i in range(4):
                key_pairs_vec[i] = get_key_pairs(p0, ptag0, i, diff2k5)

            calc_key = get_key_suggestion(pairs[pair_index], aes, verbose, key_pairs_vec, k0real, num_cipher_for_check) # <= ERREUR
            if calc_key is not None:
                break
        print ('\nreal key number', key_index, [k0real, k5, k10, k15], "\n")
        print ('calc key', calc_key, ' from pair index ', pair_index, "\n")
        total_run += 1
        if calc_key is not None:
            total_key_find += 1
            good_key = calc_key[0] == [k0real, k5, k10, k15]
            print ('good key? ', good_key, "\n")
            if good_key:
                total_key_find_good += 1
                pair_found.append(pair_index)
        print ('found good', total_key_find_good, ' out of found ', total_key_find, ' out of', total_run, '\n')

    ### Data analysis
    pair_found.sort()
    pair_found = np.array(pair_found)
    prob = np.zeros(len(pairs))
    for i in range(len(pairs)):
        prob[i] = sum(pair_found <= i)
    prob = prob  * 1.0 / total_run

    ### Save in file
    if struct_pairs:
        filename = 'RB%dStruct.pickle' % len(key)
    else:
        filename = 'RB%d.pickle' % len(key)
    print('Filename is ', filename)
    with open(filename, 'wb') as handle:
        pickle.dump([pairs, pair_found, total_key_find_good], handle)

    ### Plot graph
    plt.plot(range(len(pairs)), prob)
    plt.xlabel("Number of Plaintext Pairs")
    plt.ylabel("Attack success probability")
    plt.show()

    return

main()