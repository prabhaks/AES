/*
 * aes.c
 *
 *  Created on: Apr 11, 2015
 *      Author: prabhaks
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/md5.h>

static unsigned char **doProcessKeyExpand(char *);
static void SubWord(unsigned char *);
static void RotWord(unsigned char *);
unsigned char **S = NULL, **INVS = NULL, **P = NULL, **INVP = NULL;
int table_check = 1;

static unsigned char INV[16][16] = { { 0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b,
		0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7 }, { 0x74, 0xb4,
		0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40,
		0xee, 0xb2 }, { 0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1,
		0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2 },
		{ 0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20,
				0x6f, 0x77, 0xbb, 0x59, 0x19 },
		{ 0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab,
				0x13, 0x54, 0x25, 0xe9, 0x09 },
		{ 0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22,
				0xf0, 0x51, 0xec, 0x61, 0x17 },
		{ 0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91,
				0xdf, 0x33, 0x93, 0x21, 0x3b },
		{ 0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0,
				0x06, 0xa1, 0xfa, 0x81, 0x82 },
		{ 0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95,
				0xd9, 0xf7, 0x02, 0xb9, 0xa4 },
		{ 0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f,
				0x88, 0xf9, 0xdc, 0x89, 0x9a },
		{ 0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12,
				0x4a, 0xce, 0xe7, 0xd2, 0x62 },
		{ 0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76,
				0x3d, 0xbd, 0xbc, 0x86, 0x57 },
		{ 0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53,
				0x04, 0x1b, 0xfc, 0xac, 0xe6 },
		{ 0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4,
				0xd5, 0x9d, 0xf8, 0x90, 0x6b },
		{ 0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7,
				0xe3, 0x5d, 0x50, 0x1e, 0xb3 },
		{ 0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d,
				0xa0, 0xcd, 0x1a, 0x41, 0x1c } };

/**
 * Helper method to free up memory
 */
static void cleanUp(unsigned char **in, int row) {
	int i;
	for (i = 0; i < row; i++) {
		free(in[i]);
	}
	free(in);
}
/*
 * Helper method to free memory of all tables
 */
static void cleanUpAllTables() {
	cleanUp(S, 16);
	cleanUp(INVS, 16);
	cleanUp(P, 1);
	cleanUp(INVP, 1);
}
// Helper method to print error message.
static void Error(char *msg) {
	fprintf(stderr, "Multiple values for key '%s' in input table file.\n", msg);
	exit(1);
}

static char convertInHex(char * name, char in) {
	if ((in < '0' || in > '9') && (in < 'a' || in > 'f')) {
		fprintf(stderr, "(%s) Error:  invalid hex character ['%c'] in %s\n",
				name, in, name);
		exit(1);
	}
	if (in >= '0' && in <= '9') {
		return (in - '0') & 0xff;
	} else
		return ((in - 'a') & 0xff) + 0x0a;
}
static void populateTable(char* name, unsigned char **inp, char *val, int i,
		int col) {
	int k, j = 0;
	char z;
	for (k = 0; k < col; k = k + 2) {
		z = 0x00;
		z |= convertInHex(name, val[k]);
		z <<= 4;
		z |= (convertInHex(name, val[k + 1]) & 0x0f);
		inp[i][j++] = z & 0xff;
	}
}
// initialize given table with it values. perform error checking for number of values read
static unsigned char** initTable(char *name, char *val, int row, int col) {
	int i;
	unsigned char **key;
	key = (unsigned char **) malloc(sizeof(unsigned char *) * (row / 2));
	for (i = 0; i < (row / 2); i++)
		key[i] = (unsigned char *) malloc(sizeof(unsigned char) * (col / 2));

	for (i = 0; i < (row / 2); i++, val = (val + col)) {
		populateTable(name, key, val, i, col);
	}
	return key;
}
// helper method to perform error ceckign by counting input values
// and matching it with  their corresponding expected values
static void countValue(int *count, char *name, unsigned char **in, int row,
		int col) {
	int i, j;
	for (i = 0; i < 256; i++)
		count[i] = 0;
	for (i = 0; i < row; i++) {
		for (j = 0; j < col; j++) {
			count[in[i][j]]++;
		}
	}
}

static unsigned char xtime(unsigned char b) {
	unsigned char last_bit = b & 0x80;
	b <<= 1;
	if (last_bit == 0x80) {
		b = b ^ 0x1b;
	}
	return b;
}
static char bigDotProduct(unsigned char a, unsigned char b) {
	int i;
	unsigned char v[8];
	v[0] = b;
	for (i = 1; i < 8; i++) {
		v[i] = xtime(v[i - 1]);
	}
	unsigned char mask = 0x01;
	unsigned char result = 0x00;
	for (i = 0; i < 8; i++) {
		if ((mask & a) == mask) {
			result ^= v[i];
		}
		mask <<= 1;
	}
	return result;
}
static unsigned char* ModProduct(unsigned char *a, unsigned char *b) {
	unsigned char *res = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
	res[0] = bigDotProduct(a[0], b[3]) ^ bigDotProduct(a[1], b[2])
			^ bigDotProduct(a[2], b[1]) ^ bigDotProduct(a[3], b[0]);
	res[1] = bigDotProduct(a[1], b[3]) ^ bigDotProduct(a[2], b[2])
			^ bigDotProduct(a[3], b[1]) ^ bigDotProduct(a[0], b[0]);
	res[2] = bigDotProduct(a[2], b[3]) ^ bigDotProduct(a[3], b[2])
			^ bigDotProduct(a[0], b[1]) ^ bigDotProduct(a[1], b[0]);
	res[3] = bigDotProduct(a[3], b[3]) ^ bigDotProduct(a[0], b[2])
			^ bigDotProduct(a[1], b[1]) ^ bigDotProduct(a[2], b[0]);
	return res;
}
static void populateINVSTable() {
	int i, j;
	INVS = (unsigned char **) malloc(sizeof(unsigned char *) * 16);
	for (i = 0; i < 16; i++)
		INVS[i] = (unsigned char *) malloc(sizeof(unsigned char) * 16);
	int k = 0;
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			INVS[(int) (S[i][j] / 16)][(int) (S[i][j] % 16)] = k++;
		}
	}
}
/**
 * It parses input table file and populated table with their repective values
 * It also performs sanity check for input values so that they conform to DES specification
 */
void ProcessTableCheck(FILE *tf) {
	char *key_ptr, *value_ptr;
	char buf[1024];
	int i;
	while (fgets(buf, sizeof buf, tf) != NULL) {
		key_ptr = buf;
		value_ptr = strchr(buf, '=');
		// each line must exist in format key=value
		if (value_ptr == NULL) {
			fprintf(stderr,
					"input of table file must exist in key=value pair\n");
			exit(1);
		}
		*value_ptr = '\0';
		value_ptr++;
		if (value_ptr == NULL || strcmp(value_ptr, "") == 0) {
			fprintf(stderr, "Error : %s value can not be null or empty\n",
					key_ptr);
			exit(1);
		}
		if (value_ptr[strlen(value_ptr) - 1] == '\n') {
			value_ptr[strlen(value_ptr) - 1] = '\0';
		}
		if (strcmp("S", key_ptr) == 0) {
			if (S != NULL) {
				Error("S");
			}
			if (strlen(value_ptr) != 512) {
				fprintf(stderr,
						"Error : invalid S-box, wrong number of entries.\n");
				exit(1);
			}
			S = initTable("S", value_ptr, 32, 32);
			int *count = (int *) malloc(sizeof(int) * 256);
			countValue(count, "S", S, 16, 16);
			for (i = 0; i < 256; i++) {
				if (count[i] != 1) {
					if (count[i] == 0)
						fprintf(stderr, "Error : {%02x} not found in S box\n", i);
					else
						fprintf(stderr,
								"Error : {%02x} found %d times in S box. It should occur only once\n",
								i, count[i]);
					exit(1);
				}
			}
			free(count);
		} else if (strcmp("P", key_ptr) == 0) {
			if (P != NULL) {
				Error("P");
			}
			if (strlen(value_ptr) != 8) {
				fprintf(stderr, "Error : invalid P, wrong number of entries\n");
				exit(1);
			}
			P = initTable("P", value_ptr, 2, 8);
		} else if (strcmp("INVP", key_ptr) == 0) {
			if (INVP != NULL) {
				Error("INVP");
			}
			if (strlen(value_ptr) != 8) {
				fprintf(stderr,
						"Error : invalid INVP, wrong number of entries\n");
				exit(1);
			}
			INVP = initTable("INVP", value_ptr, 2, 8);
		} else {
			fprintf(stderr, "Invalid input key %s in table file.\n", key_ptr);
			exit(1);
		}
	}
	if (!feof(tf)) {
		fprintf(stderr,
				"Error while reading input table file. Please try running this program after sometime.\n");
		exit(1);
	}
	if (P == NULL) {
		fprintf(stderr, "Error : Missing P in table file\n");
		exit(1);
	}
	if (S == NULL) {
		fprintf(stderr, "Error : Missing S in table file\n");
		exit(1);
	}
	if (INVP == NULL) {
		fprintf(stderr, "Error : Missing INVP in table file\n");
		exit(1);
	}
	unsigned char *prod = ModProduct(*P, *INVP);
	if (prod[0] != 0x00 || prod[1] != 0x00 || prod[2] != 0x00
			|| prod[3] != 0x01) {
		fprintf(stderr, "INVP is not multiplicative inverse of P\n");
		exit(1);
	}
	populateINVSTable();
	if (table_check == 1) {
		cleanUpAllTables();
	}
}

static void copyInStateArray(unsigned char **state, char *buf) {
	int i, j, k = 0;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[j][i] = (buf[k++]);
		}
	}
}

static void AddRoundKey(unsigned char **state, unsigned char **word, int col) {
	int i, j;
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			state[j][i] ^= word[col][j];
		}
		col++;
	}
}

static void SubBytes(unsigned char **state) {
	int i;
	for (i = 0; i < 4; i++) {
		SubWord(state[i]);
	}
}
static void ShiftRows(unsigned char **state) {
	int i, j;
	for (i = 0; i < 4; i++)
		for (j = 0; j < i; j++)
			RotWord(state[i]);
}

static void MixColumns(unsigned char **state, unsigned char **X) {
	int i;
	for (i = 0; i < 4; i++) {
		unsigned char temp1 = state[0][i];
		unsigned char temp2 = state[1][i];
		unsigned char temp3 = state[2][i];
		unsigned char temp4 = state[3][i];
		state[0][i] = bigDotProduct(X[0][3], temp1)
				^ bigDotProduct(X[0][0], temp2) ^ bigDotProduct(X[0][1], temp3)
				^ bigDotProduct(X[0][2], temp4);
		state[1][i] = bigDotProduct(X[0][2], temp1)
				^ bigDotProduct(X[0][3], temp2) ^ bigDotProduct(X[0][0], temp3)
				^ bigDotProduct(X[0][1], temp4);
		state[2][i] = bigDotProduct(X[0][1], temp1)
				^ bigDotProduct(X[0][2], temp2) ^ bigDotProduct(X[0][3], temp3)
				^ bigDotProduct(X[0][0], temp4);
		state[3][i] = bigDotProduct(X[0][0], temp1)
				^ bigDotProduct(X[0][1], temp2) ^ bigDotProduct(X[0][2], temp3)
				^ bigDotProduct(X[0][3], temp4);
	}
}
static void printOut(unsigned char **state, char *inp, int k) {
	int i, j;
	if (strcmp(inp, "output") == 0) {
		printf("round[%2d].%s   ", k, inp);
	} else
		printf("round[%2d].%s    ", k, inp);
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			printf("%02x", state[j][i]);
	printf("\n");
}
static void printWord(unsigned char **word, char *name, int k, int round) {
	int i, j;
	printf("round[%2d].%s    ", round, name);
	for (i = k; i < (k + 4); i++)
		for (j = 0; j < 4; j++)
			printf("%02x", word[i][j]);
	printf("\n");
}
/*
 * This method performs encrypt operation given plaintext.
 * It read tables from tf and plaintext from fp.
 * Encrypts plainetxt using key
 */
void ProcessEncrypt(char *key, FILE *tf, FILE *fp) {
	table_check = 0;
	ProcessTableCheck(tf);
	char buf[16];
	int ret = fread(buf, 1, 16, fp);
	if (ret < 16) {
		fprintf(stderr,
				"Input size for encryption can not be less than 16 bytes\n");
		exit(1);
	}
	int i, Nr = 10, Nb = 4, round;
	unsigned char **state = (unsigned char **) malloc(
			sizeof(unsigned char *) * 4);
	for (i = 0; i < 4; i++)
		state[i] = (unsigned char *) malloc(sizeof(unsigned char) * 4);
	copyInStateArray(state, buf);
	unsigned char **word = doProcessKeyExpand(key);
	printOut(state, "input", 0);
	AddRoundKey(state, word, 0);
	printWord(word, "k_sch", 0, 0);
	for (round = 1; round < Nr; round++) {
		printOut(state, "start", round);
		SubBytes(state);
		printOut(state, "s_box", round);
		ShiftRows(state);
		printOut(state, "s_row", round);
		MixColumns(state, P);
		printOut(state, "m_col", round);
		AddRoundKey(state, word, round * Nb);
		printWord(word, "k_sch", round * Nb, round);
	}
	printOut(state, "start", round);
	SubBytes(state);
	printOut(state, "s_box", round);
	ShiftRows(state);
	printOut(state, "s_row", round);
	AddRoundKey(state, word, Nr * Nb);
	printWord(word, "k_sch", Nr * Nb, round);
	printOut(state, "output", round);
}
static void InvSubWord(unsigned char *inp) {
	inp[0] = INVS[(int) (inp[0] / 16)][(int) (inp[0] % 16)];
	inp[1] = INVS[(int) (inp[1] / 16)][(int) (inp[1] % 16)];
	inp[2] = INVS[(int) (inp[2] / 16)][(int) (inp[2] % 16)];
	inp[3] = INVS[(int) (inp[3] / 16)][(int) (inp[3] % 16)];
}

static void InvSubBytes(unsigned char **state) {
	int i;
	for (i = 0; i < 4; i++) {
		InvSubWord(state[i]);
	}
}
static void InvShiftRows(unsigned char **state) {
	int i, j;
	for (i = 3; i >= 0; i--)
		for (j = 3; j >= i; j--)
			RotWord(state[i]);
}
static void printOutD(unsigned char **state, char *inp, int k) {
	int i, j;
	if (strcmp(inp, "ioutput") == 0) {
		printf("round[%2d].%s  ", k, inp);
	} else
		printf("round[%2d].%s   ", k, inp);
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			printf("%02x", state[j][i]);
	printf("\n");
}
static void printWordD(unsigned char **word, char *name, int k, int round) {
	int i, j;
	printf("round[%2d].%s   ", round, name);
	for (i = k; i < (k + 4); i++)
		for (j = 0; j < 4; j++)
			printf("%02x", word[i][j]);
	printf("\n");
}
/**
 * This method performs decrypt operation given cipher.
 * It read tables from tf and ciphertext from fp.
 * Decrypts using key. Using fiestel structure, decrypts is nothigs but encryption
 * with reverse round keys input.
 */
void ProcessDecrypt(char *key, FILE *tf, FILE *fp) {
	table_check = 0;
	ProcessTableCheck(tf);
	char buf[16];
	int ret = fread(buf, 1, 16, fp);
	if (ret < 16) {
		fprintf(stderr,
				"Input size for decryption can not be less than 16 bytes\n");
		exit(1);
	}
	int i, Nr = 10, Nb = 4, round;
	unsigned char **state = (unsigned char **) malloc(
			sizeof(unsigned char *) * 4);
	for (i = 0; i < 4; i++)
		state[i] = (unsigned char *) malloc(sizeof(unsigned char) * 4);
	copyInStateArray(state, buf);
	unsigned char **word = doProcessKeyExpand(key);
	printOutD(state, "iinput", 0);
	AddRoundKey(state, word, Nr * Nb);
	printWordD(word, "ik_sch", Nr * Nb, 0);
	for (round = Nr - 1; round > 0; round--) {
		printOutD(state, "istart", Nr - round);
		InvShiftRows(state);
		printOutD(state, "is_row", Nr - round);
		InvSubBytes(state);
		printOutD(state, "is_box", Nr - round);
		AddRoundKey(state, word, round * Nb);
		printWordD(word, "ik_sch", round * Nb, Nr - round);
		printOutD(state, "ik_add", Nr - round);
		MixColumns(state, INVP);
	}
	printOutD(state, "istart", Nr - round);
	InvShiftRows(state);
	printOutD(state, "is_row", Nr - round);
	InvSubBytes(state);
	printOutD(state, "is_box", Nr - round);
	AddRoundKey(state, word, 0);
	printWordD(word, "ik_sch", round * Nb, Nr - round);
	printOutD(state, "ioutput", Nr - round);
}

void ProcessModProd(char* poly1, char* poly2) {
	table_check = 0;
	if (poly1 == NULL || poly2 == NULL || strlen(poly1) != 8
			|| strlen(poly2) != 8) {
		fprintf(stderr,
				"Invalid input poly. Please make sure each poly1 and poly2 are of length 8 in hexstring\n");
		exit(1);
	}
	P = initTable("P1", poly1, 2, 8);
	INVP = initTable("P2", poly2, 2, 8);
	unsigned char * res = ModProduct(*P, *INVP);
	printf(
			"{%02x}{%02x}{%02x}{%02x} CIRCLEX {%02x}{%02x}{%02x}{%02x} = {%02x}{%02x}{%02x}{%02x}\n",
			P[0][0], P[0][1], P[0][2], P[0][3], INVP[0][0], INVP[0][1],
			INVP[0][2], INVP[0][3], res[0], res[1], res[2], res[3]);
}
static void populateWord(unsigned char *word, char *key, int i) {
	word[0] = ((convertInHex("input key", key[8 * i]) << 4)
			| (convertInHex("input key", key[8 * i + 1]) & 0x0f)) & 0xff;
	word[1] = ((convertInHex("input key", key[8 * i + 2]) << 4)
			| (convertInHex("input key", key[8 * i + 3]) & 0x0f)) & 0xff;
	word[2] = ((convertInHex("input key", key[8 * i + 4]) << 4)
			| (convertInHex("input key", key[8 * i + 5]) & 0x0f)) & 0xff;
	word[3] = ((convertInHex("input key", key[8 * i + 6]) << 4)
			| (convertInHex("input key", key[8 * i + 7]) & 0x0f)) & 0xff;
}
static void SubWord(unsigned char *inp) {
	inp[0] = S[(int) (inp[0] / 16)][(int) (inp[0] % 16)];
	inp[1] = S[(int) (inp[1] / 16)][(int) (inp[1] % 16)];
	inp[2] = S[(int) (inp[2] / 16)][(int) (inp[2] % 16)];
	inp[3] = S[(int) (inp[3] / 16)][(int) (inp[3] % 16)];
}
static void RotWord(unsigned char *inp) {
	unsigned char temp = inp[0];
	inp[0] = inp[1];
	inp[1] = inp[2];
	inp[2] = inp[3];
	inp[3] = temp;
}
static void addRoundConstant(unsigned char *inp, int i) {
	unsigned char temp = 0x01;
	int j;
	for (j = 1; j < i; j++) {
		temp = bigDotProduct(temp, 0x02);
	}
	inp[0] = (temp ^ inp[0]);
}
static void calXOR(unsigned char *dest, unsigned char *src1,
		unsigned char *src2) {
	dest[0] = src1[0] ^ src2[0];
	dest[1] = src1[1] ^ src2[1];
	dest[2] = src1[2] ^ src2[2];
	dest[3] = src1[3] ^ src2[3];
}
static void doKeyExpand(char *key, unsigned char **word) {
	int i;
	int Nk = 4, Nr = 10, Nb = 4;
	for (i = 0; i < Nk; i++) {
		populateWord(word[i], key, i);
	}
	unsigned char *temp = (unsigned char *) malloc(sizeof(unsigned char) * 4);
	for (i = Nk; i < (Nb * (Nr + 1)); i++) {
		memcpy(temp, word[i - 1], 4);
		if ((i % Nk) == 0) {
			RotWord(temp);
			SubWord(temp);
			addRoundConstant(temp, (i / Nk));
		}
		calXOR(word[i], word[i - Nk], temp);
	}
}
static unsigned char **doProcessKeyExpand(char *key) {
	if (key == NULL || strlen(key) != 32) {
		fprintf(stderr,
				"Invalid input key %s. The key length should be exactly 32 in hexstring representation.\n",
				key);
		exit(1);
	}
	int i;
	unsigned char **word = (unsigned char **) malloc(
			sizeof(unsigned char *) * 44);
	for (i = 0; i < 44; i++)
		word[i] = (unsigned char *) malloc(sizeof(unsigned char) * 4);
	doKeyExpand(key, word);
	return word;
}

void ProcessKeyExpand(char* key, FILE* tf) {
	table_check = 0;
	ProcessTableCheck(tf);
	int i;
	unsigned char **word = doProcessKeyExpand(key);
	for (i = 0; i < 44; i++) {
		printf("w[%2d]: ", i);
		printf("%02x%02x%02x%02x\n", word[i][0], word[i][1], word[i][2],
				word[i][3]);
	}
}

static void printInvOut(unsigned char *a, unsigned char *b, unsigned char*c,
		int i) {
	printf(
			"i=%d, rem[i]={%02x}{%02x}{%02x}{%02x}, quo[i]={%02x}{%02x}{%02x}{%02x}, aux[i]={%02x}{%02x}{%02x}{%02x}\n",
			i, a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2],
			c[3]);
}
static int calculateDegree(unsigned char *poly) {
	if (poly[0] != 0x0)
		return 3;
	else if (poly[1] != 0x0)
		return 2;
	else if (poly[2] != 0x0)
		return 1;
	else
		return 0;
}
static void calLongHangDiv(unsigned char *rem1, unsigned char*rem2,
		unsigned char *quot, int remDegree, int quotDegree) {
	int tempQD = quotDegree;
	int tempRD = remDegree;
	int rem1D = 3;
	unsigned char x = 0x01;
	while (rem1D >= remDegree) {
		unsigned char inv = INV[(int) (rem2[3 - remDegree] / 16)][(int) (rem2[3
				- remDegree] % 16)];
		quot[3 - tempQD] = bigDotProduct(inv, x);
		int i = 0;
		while (--tempRD >= 0) {
			rem1[3 - rem1D + i] = rem1[3 - rem1D + i]
					^ (bigDotProduct(rem2[3 - tempRD], quot[3 - tempQD]));
			i++;
		}
		tempQD--;
		rem1D = calculateDegree(rem1);
		x = rem1[3 - rem1D];
		tempRD = remDegree + 1;
	}
}

static void calLongHangDiv2(unsigned char *rem1, unsigned char *rem2,
		unsigned char *quot, int remDegree, int quotDegree) {
	int tempQD = quotDegree;
	int tempRD = remDegree;
	int rem1D = calculateDegree(rem1);
	unsigned char x = rem1[3 - rem1D];
	while (rem1D >= remDegree) {
		unsigned char inv = INV[(int) (rem2[3 - remDegree] / 16)][(int) (rem2[3
				- remDegree] % 16)];
		quot[3 - tempQD] = bigDotProduct(inv, x);
		int i = 0;
		while (tempRD >= 0) {
			rem1[3 - rem1D + i] = rem1[3 - rem1D + i]
					^ (bigDotProduct(rem2[3 - tempRD], quot[3 - tempQD]));
			i++;
			tempRD--;
		}
		tempQD--;
		rem1D = calculateDegree(rem1);
		x = rem1[3 - rem1D];
		tempRD = remDegree;
	}
}
static void specialDiv(unsigned char *rem1, unsigned char *rem2,
		unsigned char *quot, int remDegree, int quotDegree) {
	int tempQD = quotDegree;
	int rem1D = calculateDegree(rem1);
	unsigned char x = rem1[3 - rem1D];
	unsigned char inv;
	while (rem1D > remDegree) {
		inv = INV[(int) (rem2[3] / 16)][(int) (rem2[3] % 16)];
		quot[3 - tempQD] = bigDotProduct(inv, x);
		rem1[3 - rem1D] = rem1[3 - rem1D]
				^ (bigDotProduct(rem2[3], quot[3 - tempQD]));
		tempQD--;
		rem1D = calculateDegree(rem1);
		x = rem1[3 - rem1D];
	}
	quot[3 - tempQD] = bigDotProduct(inv, (x ^ 0x01));
	rem1[3 - rem1D] = rem1[3 - rem1D]
			^ (bigDotProduct(rem2[3], quot[3 - tempQD]));

}
static void calAux(unsigned char *quo, unsigned char *aux1, unsigned char *aux2) {
	int i;
	unsigned char *res = ModProduct(quo, aux2);
	for (i = 0; i < 4; i++) {
		aux1[i] = aux1[i] ^ res[i];
	}
}
static int checkEmpty(unsigned char * inp) {
	if ((inp[0] == 0x0) && (inp[1] == 0x0) && (inp[2] == 0x0)
			&& (inp[3] == 0x0)) {
		return 1;
	}
	return 0;
}
static void printNoInv(unsigned char * inp) {
	printf("{%02x}{%02x}{%02x}{%02x} does not have a multiplicative inverse.\n",
			inp[0], inp[1], inp[2], inp[3]);
}
static void printOutInv(unsigned char * inp, unsigned char * out) {
	printf(
			"Multiplicative inverse of {%02x}{%02x}{%02x}{%02x} is {%02x}{%02x}{%02x}{%02x}\n",
			inp[0], inp[1], inp[2], inp[3], out[0], out[1], out[2], out[3]);
}
static void initQuot(unsigned char * quot) {
	int i;
	for (i = 0; i < 4; i++) {
		quot[i] = 0x00;
	}
}
void ProcessInverse(char* poly) {
	table_check = 0;
	int i, k;
	if (poly == NULL || strlen(poly) != 8) {
		fprintf(stderr,
				"Error : polynomial length should be exactly equal to 4 bytes (8 hex string chars)\n");
		exit(1);
	}
	unsigned char *rem1 = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
	for (i = 0; i < 3; i++) {
		rem1[i] = 0x00;
	}
	rem1[i] = 0x01;
	unsigned char *rem2 = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
	for (i = 0, k = 0; i < 8; i = i + 2) {
		rem2[k++] = ((convertInHex("input polynomial", poly[i]) << 4)
				| (convertInHex("input polynomial", poly[i + 1]) & 0x0f))
				& 0xff;
	}
	unsigned char *orig_poly = (unsigned char *) malloc(
			sizeof(unsigned char *) * 4);
	memcpy(orig_poly, rem2, 4);
	unsigned char *quot = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
	initQuot(quot);
	unsigned char *aux1 = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
	for (i = 0; i < 4; i++) {
		aux1[i] = 0x00;
	}
	unsigned char *aux2 = (unsigned char *) malloc(sizeof(unsigned char *) * 4);
	for (i = 0; i < 3; i++) {
		aux2[i] = 0x00;
	}
	aux2[i] = 0x01;
	printInvOut(rem1, quot, aux1, 1);
	printInvOut(rem2, quot, aux2, 2);
	int remDegree, quotDegree, prevDegree = 4;
	remDegree = calculateDegree(rem2);
	quotDegree = prevDegree - remDegree;
	initQuot(quot);
	if (remDegree == 0) {
		specialDiv(rem1, rem2, quot, remDegree, quotDegree);
		calAux(quot, aux1, aux2);
		printInvOut(rem1, quot, aux1, 3);
		printOutInv(orig_poly, aux1);
		return;
	}
	calLongHangDiv(rem1, rem2, quot, remDegree, quotDegree);
	calAux(quot, aux1, aux2);
	printInvOut(rem1, quot, aux1, 3);
	if (checkEmpty(rem1) == 1) {
		printNoInv(orig_poly);
		return;
	}
	prevDegree = remDegree;
	remDegree = calculateDegree(rem1);
	quotDegree = prevDegree - remDegree;
	initQuot(quot);
	if (remDegree == 0) {
		specialDiv(rem2, rem1, quot, remDegree, quotDegree);
		calAux(quot, aux2, aux1);
		printInvOut(rem2, quot, aux2, 4);
		printOutInv(orig_poly, aux2);
		return;
	}
	calLongHangDiv2(rem2, rem1, quot, remDegree, quotDegree);
	calAux(quot, aux2, aux1);
	printInvOut(rem2, quot, aux2, 4);
	if (checkEmpty(rem2) == 1) {
		printNoInv(orig_poly);
		return;
	}

	prevDegree = remDegree;
	remDegree = calculateDegree(rem2);
	quotDegree = prevDegree - remDegree;
	initQuot(quot);
	if (remDegree == 0) {
		specialDiv(rem1, rem2, quot, remDegree, quotDegree);
		calAux(quot, aux1, aux2);
		printInvOut(rem1, quot, aux1, 5);
		printOutInv(orig_poly, aux1);
		return;
	}
	calLongHangDiv2(rem1, rem2, quot, remDegree, quotDegree);
	calAux(quot, aux1, aux2);
	printInvOut(rem1, quot, aux1, 5);
	if (checkEmpty(rem1) == 1) {
		printNoInv(orig_poly);
		return;
	}
	prevDegree = remDegree;
	remDegree = calculateDegree(rem1);
	quotDegree = prevDegree - remDegree;
	initQuot(quot);
	if (remDegree == 0) {
		specialDiv(rem2, rem1, quot, remDegree, quotDegree);
		calAux(quot, aux2, aux1);
		printInvOut(rem2, quot, aux2, 6);
		printOutInv(orig_poly, aux2);
		return;
	}

}
