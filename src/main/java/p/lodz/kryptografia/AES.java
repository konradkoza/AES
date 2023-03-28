package p.lodz.kryptografia;

import java.util.Arrays;


public class AES {
    private byte[][] roundKeys;
    private int Nb = 4, Nk, Nr;


    private final int[] sbox = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
            0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
            0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
            0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
            0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
            0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
            0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
            0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
            0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
            0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
            0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
            0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
            0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
            0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
            0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
            0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
            0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
            0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
            0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
            0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

    private final int[] invSbox = {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
            0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
            0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
            0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
            0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
            0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
            0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
            0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
            0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
            0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
            0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
            0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
            0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
            0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
            0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
            0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
            0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
            0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
            0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
            0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
            0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

    private final int[][] rCon = {
            {0x00, 0x00, 0x00, 0x00},
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1B, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00},
    };



    private byte[][] expandKey(byte[] key) {
        byte[][] w = new byte[Nb * (Nr + 1)][Nb];
        byte[] temp = new byte[4];
        int i = 0;
        while (i < Nk) {
            w[i] = new byte[]{key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};

            i++;
        }
        i = Nk;
        while (i <Nb * (Nr + 1)) {
            temp = w[i - 1];
            if (i % Nk == 0) {
                temp = SubWord(rotWord(temp));
                for (int k = 0; k < 4; k++) {
                    temp[k] ^= rCon[i / Nk][k];
                }
            } else if (Nk > 6 && i % Nk == 4) {
                temp = SubWord(temp);
            }
            w[i] = xorBytes(w[i - Nk], temp);
            i++;
        }

        return w;
    }

    private byte[] xorBytes(byte[] a, byte[] b) {
        byte[] temp = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            temp[i] = (byte) (a[i] ^ b[i]);
        }
        return temp;
    }

    private byte[] SubWord(byte[] word) {
        byte[] temp = new byte[word.length];
        for (int i = 0; i < temp.length; i++) {
            int row = (word[i] >> 4) & 0x0f;
            int col = word[i] & 0x0f;
            temp[i] = (byte) (sbox[(16 * row) + col] & 0xff);
        }
        return temp;
    }

    private byte[] rotWord(byte[] word) {
        byte[] temp = new byte[word.length];
        temp[0] = word[1];
        temp[1] = word[2];
        temp[2] = word[3];
        temp[3] = word[0];
        return temp;
    }

    private byte[][] addRoundKey(byte[][] state, byte[][] w, int round) {
        byte[][] temp = new byte[state.length][state[0].length];
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j][i] = (byte) (state[j][i] ^ w[round * Nb + i][j]);
            }
        }
        return temp;
    }

    private void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = (byte) (sbox[(state[i][j] & 0xff)]);
            }
        }
    }

    private void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = (byte) (invSbox[(state[i][j] & 0xff)]);
            }
        }
    }


    private void shiftRows(byte[][] state) {
        byte[] temp = new byte[4];
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                temp[j] = state[i][(j + i) % Nb];
            }
            System.arraycopy(temp, 0, state[i], 0, Nb);
        }
    }

    private void invShiftRows(byte[][] state) {
        byte[] temp = new byte[4];
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                temp[(i + j) % Nb] = state[i][j];
            }
            System.arraycopy(temp, 0, state[i], 0, Nb);
        }
    }

    private void mixColumns(byte[][] state) {
        byte[] tmp = new byte[4];
        byte b02 = 0x02;
        byte b03 = 0x03;
        for (int i = 0; i < 4; i++) {
            tmp[0] = (byte) (gfMul(b02, state[i][0]) ^ gfMul(b03, state[i][1]) ^ state[i][2] ^ state[i][3]);
            tmp[1] = (byte) (state[i][0] ^ gfMul(b02, state[i][1]) ^ gfMul(b03, state[i][2]) ^ state[i][3]);
            tmp[2] = (byte) (state[i][0] ^ state[i][1] ^ gfMul(b02, state[i][2]) ^ gfMul(b03, state[i][3]));
            tmp[3] = (byte) (gfMul(b03, state[i][0]) ^ state[i][1] ^ state[i][2] ^ gfMul(b02, state[i][3]));
            System.arraycopy(tmp, 0, state[i], 0, 4);
        }
    }


    private void invMixColumns(byte[][] state) {
        byte[] tmp = new byte[4];
        byte b0e = 0x0e,  b0b = 0x0b, b0d = 0x0d, b09 = 0x09;
        for (int i = 0; i < 4; i++) {
            tmp[0] = (byte) (gfMul(b0e, state[i][0]) ^ gfMul(b0b, state[i][1]) ^ gfMul(b0d, state[i][2]) ^gfMul(b09, state[i][3]));
            tmp[1] = (byte) (gfMul(b09, state[i][0]) ^ gfMul(b0e, state[i][1]) ^ gfMul(b0b, state[i][2]) ^ gfMul(b0d, state[i][3]));
            tmp[2] = (byte) (gfMul(b0d, state[i][0]) ^ gfMul(b09, state[i][1]) ^ gfMul(b0e, state[i][2]) ^ gfMul(b0b, state[i][3]));
            tmp[3] = (byte) (gfMul(b0b, state[i][0]) ^ gfMul(b0d, state[i][1]) ^ gfMul(b09, state[i][2]) ^ gfMul(b0e, state[i][3]));
            System.arraycopy(tmp, 0, state[i], 0, 4);
        }
    }


    private byte gfMul(byte a, byte b) {
        byte p = 0, hi_bit_set;
            for (int i = 0; i < 8; i++) {
                if ((b & 1) != 0) {
                    p = (byte) (p ^ a);
                }
                hi_bit_set = (byte) (a & 0x80);
                a = (byte) (a << 1);
                if (hi_bit_set != 0) {
                    a = (byte) (a ^ 0x1b); // irreducible polynomial of GF(2^8) x^8 + x^4 + x^3 + x + 1
                }
                b = (byte) ((b & 0xff) >> 1);
            }

        return p;
    }

    private byte[] cipher(byte[] in) {
        byte[] temp = new byte[in.length];
        byte[][] state = new byte[4][Nb];
        for (int i = 0; i < in.length; i++) {
            state[i / 4][i % 4] = in[i];
        }
        state = addRoundKey(state, roundKeys, 0);
        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            state = addRoundKey(state, roundKeys, round);
        }
        subBytes(state);
        shiftRows(state);
        state = addRoundKey(state, roundKeys, Nr);
        for (int i = 0; i < temp.length; i++) {
            temp[i] = state[i / 4][i % 4];
        }

        return temp;
    }

    private byte[] invCipher(byte[] in) {
        byte[] temp = new byte[in.length];
        byte[][] state = new byte[4][Nb];
        for (int i = 0; i < in.length; i++) {
            state[i / 4][i % 4] = in[i];
        }
        state = addRoundKey(state, roundKeys, Nr);
        for (int round = Nr - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            state = addRoundKey(state, roundKeys, round);
            invMixColumns(state);

        }
        invShiftRows(state);
        invSubBytes(state);
        state = addRoundKey(state, roundKeys, 0);
        for (int i = 0; i < temp.length; i++) {
            temp[i] = state[i / 4][i % 4];
        }

        return temp;
    }

    public byte[] encrypt(byte[] message, byte[] key) {
        Nk = key.length / 4;
        Nr = Nk + 6;
        roundKeys = expandKey(key);

        byte[] temp = addPadding(message);
        byte[] result = new byte[temp.length];
        byte[] block = new byte[16];


        for (int i = 0; i < temp.length; i += 16) {
            block = Arrays.copyOfRange(temp, i, i + 16);
            block = cipher(block);
            System.arraycopy(block, 0, result, i, 16);
        }

        return result;
    }

    private static byte[] addPadding(byte[] data) {
        int paddingLength = 16 - (data.length % 16);
        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        byte paddingByte = (byte) paddingLength;
        Arrays.fill(paddedData, data.length, paddedData.length, paddingByte);
        return paddedData;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[] temp = new byte[ciphertext.length];
        byte[] block = new byte[16];
        Nk = key.length / 4;
        Nr = Nk + 6;
        roundKeys = expandKey(key);

        for (int i = 0; i < ciphertext.length; i += 16) {
            block = Arrays.copyOfRange(ciphertext, i, i + 16);
            block = invCipher(block);
            System.arraycopy(block, 0, temp, i, 16);
        }
        temp = removePadding(temp);

        return temp;
    }

    private static byte[] removePadding(byte[] decoded) {
        int paddingCount = decoded[decoded.length-1];
        return Arrays.copyOfRange(decoded, 0, decoded.length - paddingCount);
    }
}
