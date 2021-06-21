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

import sys
import numpy as np

def bytes_from_hex(hex_str):
    return bytes.fromhex(hex_str)

def print_hex_str(hex_str, msg=''):
    print(msg, list(map(hex, hex_str)))