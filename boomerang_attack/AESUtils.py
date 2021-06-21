# Copyright (C) 2019 Eyal Ronen <er [at] eyalro [dot] net>

# This file is a part of the AES-Cryptoanalysis code.

# This file may be used under the terms of the GNU General Public License
# version 3 as published by the Free Software Foundation and appearing in
# the file LICENSE.GPL included in the packaging of this file.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from aes import AES
import struct
import numpy as np

SBOX = np.array(AES.Sbox, dtype=np.uint8)

def Gmul(a, b):
    px = 0x1b

    p = 0
    for i in range(8):
      if ((b & 1) == 1):
          p ^= a
      high = (a & 0x80)
      a <<= 1
      a &= 0xff
      if(high == 0x80):
          a ^= px
      b >>= 1

    return p

def getGmulInv(a):
    mul = list(map(lambda x: Gmul(a, x), range(256)))
    res = [x for x in range(256) if mul[x] == 1]
    return res[0]

def mix_col(plain, key):
    bytes = np.array(plain, dtype=np.uint8) ^ np.array(key, dtype=np.uint8)
    bytes = SBOX[bytes]
    column = [0]*4
    column[0] = (Gmul(bytes[0], 2) ^ Gmul(bytes[3], 1) ^ Gmul(bytes[2], 1) ^ Gmul(bytes[1], 3)) & 0xff
    column[1] = (Gmul(bytes[1], 2) ^ Gmul(bytes[0], 1) ^ Gmul(bytes[3], 1) ^ Gmul(bytes[2], 3)) & 0xff
    column[2] = (Gmul(bytes[2], 2) ^ Gmul(bytes[1], 1) ^ Gmul(bytes[0], 1) ^ Gmul(bytes[3], 3)) & 0xff
    column[3] = (Gmul(bytes[3], 2) ^ Gmul(bytes[2], 1) ^ Gmul(bytes[1], 1) ^ Gmul(bytes[0], 3)) & 0xff
    return np.array(column, dtype=np.uint8)

