# Laetitia Debesse, Sihem Mesnager, Mounira Msahli, 2020-2021
# Based on https://github.com/eyalr0/AES-Cryptoanalysis

import pickle
import matplotlib.pyplot as plt
import numpy as np
from math import log

total_run = 500

with open('RB500Struct_Nitaj.pickle', 'rb') as handle:
    [pairs_n, pair_found_n, total_key_find_good_n] = pickle.load(handle)

prob_n = np.zeros(len(pairs_n))
for i in range(len(pairs_n)):
    prob_n[i] = sum(pair_found_n <= i)
prob1_n = prob_n * 1.0 / total_run
num_pairs1_n = range(1, len(pairs_n) + 1)

with open('RB500Struct_Cui.pickle', 'rb') as handle2:
    [pairs_c, pair_found_c, total_key_find_good_c] = pickle.load(handle2)

prob_c = np.zeros(len(pairs_c))
for i in range(len(pairs_c)):
    prob_c[i] = sum(pair_found_c <= i)
prob1_c = prob_c * 1.0 / total_run
num_pairs1_c = range(1, len(pairs_c) + 1)

with open('RB500Struct_Rijndael.pickle', 'rb') as handle3:
    [pairs_r, pair_found_r, total_key_find_good_r] = pickle.load(handle3)

prob_r = np.zeros(len(pairs_r))
for i in range(len(pairs_r)):
    prob_r[i] = sum(pair_found_r <= i)
prob1_r = prob_r * 1.0 / total_run
num_pairs1_r = range(1, len(pairs_r) + 1)

plt.plot(num_pairs1_r, prob1_r, 'b-', label="Rijndael s-box")
plt.plot(num_pairs1_c, prob1_c, 'r-', label="J. Cui et al. s-box")
plt.plot(num_pairs1_n, prob1_n, 'g-', label="A. Nitaj et al. s-box")

plt.legend(loc='upper left')
plt.ylabel('Attack Success Probability')
plt.xlabel('Number of Plaintext Pairs')
plt.savefig("results.eps", format='eps')
plt.show()

print(total_key_find_good_n)