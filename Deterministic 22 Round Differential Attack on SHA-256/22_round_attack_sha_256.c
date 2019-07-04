#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHUNK_SIZE 64
#define TOTAL_LEN_LEN 8
#define ROT_R(x, y) (x >> y | x << (32 - y))
#define sigma_0(x) (ROT_R((x), 7) ^ ROT_R((x), 18) ^ ((x) >> 3))
#define sigma_1(x) (ROT_R((x), 17) ^ ROT_R((x), 19) ^ ((x) >> 10))
#define SIGMA_0(x) (ROT_R((x), 2) ^ ROT_R((x), 13) ^ ROT_R((x), 22))
#define SIGMA_1(x) (ROT_R((x), 6) ^ ROT_R((x), 11) ^ ROT_R((x), 25))
#define IF(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

const uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t reg[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static inline void compression_step(int step, uint32_t * W){
	const uint32_t temp1 = reg[7] + SIGMA_1(reg[4]) + IF(reg[4], reg[5], reg[6]) + K[step] + W[step];
	const uint32_t temp2 = SIGMA_0(reg[0]) + MAJ(reg[0], reg[1], reg[2]);

	reg[7] = reg[6];
	reg[6] = reg[5];
	reg[5] = reg[4];
	reg[4] = reg[3] + temp1;
	reg[3] = reg[2];
	reg[2] = reg[1];
	reg[1] = reg[0];
	reg[0] = temp1 + temp2;
}

static inline void info_print(int step){
	printf("Step %02d:\ta: %08x\t| b: %08x\t| c: %08x\t| d: %08x\t| e: %08x\n", step, reg[0], reg[1], reg[2], reg[3], reg[4]);
}

static inline void msg_exp_step(int index, uint32_t * W){
	W[index] = W[index - 16] + sigma_0(W[index - 15]) + W[index - 7] + sigma_1(W[index - 2]);
}

static inline uint32_t W_to_set_reg_A(int step, uint32_t a){
	return (a - SIGMA_0(reg[0]) - MAJ(reg[0], reg[1], reg[2]) - SIGMA_1(reg[4]) - IF(reg[4], reg[5], reg[6]) - reg[7] - K[step]);
}

static inline uint32_t W_to_set_reg_E(int step, uint32_t e){
	return (e - reg[3] - SIGMA_1(reg[4]) - IF(reg[4], reg[5], reg[6]) - reg[7] - K[step]);
}

int main(){
	uint32_t W[22];
	srand((unsigned int)clock());
	W[0] = rand();
	srand((unsigned int)clock());
	W[1] = rand();
	srand((unsigned int)clock());
	W[14] = rand();
	srand((unsigned int)clock());
	W[15] = rand();
	
	uint32_t del_W[16] = {0};
	del_W[7] = 1;
	del_W[15] = -1;

	const uint32_t DELTA = sigma_1(W[15]) - sigma_1(W[15] - 1);
	printf("DELTA:\t\t\t\t%08x\n\n", DELTA);

	compression_step(0, W);
	compression_step(1, W);
	
	W[2] = W_to_set_reg_A(2, DELTA - 1 + MAJ(-1, -2, DELTA - 3));
	compression_step(2, W);
	
	W[3] = W_to_set_reg_A(3, DELTA - 3);
	compression_step(3, W);
	
	W[4] = W_to_set_reg_A(4, -2);
	compression_step(4, W);
	
	W[5] = W_to_set_reg_A(5, -1);
	compression_step(5, W);
	
	W[6] = W_to_set_reg_A(6, -1);
	compression_step(6, W);
	
	W[7] = W_to_set_reg_A(7, -1);
	compression_step(7, W);
	
	del_W[8] = -1 - (IF((reg[4] + 1), reg[5], reg[6]) - IF(reg[4], reg[5], reg[6])) - (SIGMA_1((reg[4] + 1)) - SIGMA_1(reg[4]));

	W[8] = W_to_set_reg_A(8, 0);
	compression_step(8, W);
	
	W[9] = W_to_set_reg_A(9, 0);
	compression_step(9, W);
	
	del_W[10] = SIGMA_1(reg[4]) - IF((reg[4] - 1), (reg[5] - 1), (reg[6] + 1)) + IF(reg[4], reg[5], reg[6]) - SIGMA_1((reg[4] - 1));

	W[10] = W_to_set_reg_E(10, -1);
	compression_step(10, W);
	
	W[11] = W_to_set_reg_E(11, -1);
	compression_step(11, W);
	
	W[12] = W_to_set_reg_E(12, -1);
	compression_step(12, W);
	
	W[13] = W_to_set_reg_E(13, -1);
	compression_step(13, W);
	
	uint32_t W_dash[22];

	printf("W\t\tdel_W\t\tW_dash\n");
	int i;
	for (i = 0; i < 16; ++i) {
		printf("%08x\t", W[i]);
		printf("%08x\t", del_W[i]);
		W_dash[i] = W[i] + del_W[i];
		printf("%08x\n", W_dash[i]);
	}

	printf("\n");

	int step;
	for (step = 14; step < 16; step++) {
		compression_step(step, W);
	}

	for (step = 16; step < 22; step++) {
		msg_exp_step(step, W);
		W_dash[step] = W[step];
	}

	for (step = 16; step < 22; step++) {
		compression_step(step, W);
	}

	printf("\nValue of Registers upto 22 Steps for W:\n");
	printf("%08x\n", reg[0]);
	printf("%08x\n", reg[1]);
	printf("%08x\n", reg[2]);
	printf("%08x\n", reg[3]);
	printf("%08x\n", reg[4]);
	printf("%08x\n", reg[5]);
	printf("%08x\n", reg[6]);
	printf("%08x\n", reg[7]);

	reg[0] = 0x6a09e667;
	reg[1] = 0xbb67ae85;
	reg[2] = 0x3c6ef372;
	reg[3] = 0xa54ff53a;
	reg[4] = 0x510e527f;
	reg[5] = 0x9b05688c;
	reg[6] = 0x1f83d9ab;
	reg[7] = 0x5be0cd19;

	for (step = 0; step < 22; step++) {
		compression_step(step, W_dash);
	}

	printf("\nValue of Registers upto 22 Steps for W_dash:\n");
	printf("%08x\n", reg[0]);
	printf("%08x\n", reg[1]);
	printf("%08x\n", reg[2]);
	printf("%08x\n", reg[3]);
	printf("%08x\n", reg[4]);
	printf("%08x\n", reg[5]);
	printf("%08x\n", reg[6]);
	printf("%08x\n", reg[7]);
}