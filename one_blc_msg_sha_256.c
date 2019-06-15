#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

/*
 *	See "NOTE 1" in one of the following comments for uncommenting the following code.
 */
// uint32_t IV[8] = {
// 	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
// };

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

void hash_digest_to_hash_string(char *in_msg_hash_digest_string, 
	const uint8_t in_msg_hash_digest[32]) {
	for(size_t byte_index = 0; byte_index < 32; byte_index++) {
		in_msg_hash_digest_string += 
		sprintf(in_msg_hash_digest_string, "%02x", in_msg_hash_digest[byte_index]);
	}
}

/*
 *	Assumption:
 *	(1)	The Size of Input Message is exactly One Block (512 bits).
 */
int main(int argc, char **argv){
	/*
	 *	Extracting the Input Message from arguments to the main function.
	 */
	char *in_msg = (char *)malloc(sizeof(char)*strlen(argv[1]));
	for(int index = 0; index < strlen(argv[1]); index++){
		in_msg[index] = argv[1][index];
	}
	for (unsigned int i = 2; i <= argc - 1; ++i) {
		strcat(in_msg, " ");
		strcat(in_msg, argv[i]);
	}
	/*
	 *	Extraction of the Input Message: "Completed".
	 *	The Input Message is stored in "string" type variable named "in_msg".
	 */
	
	/*
	 *	Calculating the Partial Hash Digest of the Input Message:
	 *	(1)	No pre-processing (padding) of the Input Message is done.
	 *	(2)	Partial Hash Digest is equivalent to the Hash Digest of the One Block Input Message only (without padding).
	 */
	uint8_t in_msg_hash_digest[32];
	
	uint8_t chunk[64];
	memcpy(chunk, in_msg, CHUNK_SIZE);
	
	uint32_t W[64];
	const uint8_t *p = chunk;

	for (int i = 0; i < 16; i++) {
		W[i] = 	(uint32_t) p[0] << 24 | 
		(uint32_t) p[1] << 16 |
		(uint32_t) p[2] << 8 |
		(uint32_t) p[3];
		p += 4;
	}

	/*
	 *	Message Expansion Step
	 */
	for (int index = 16; index < 64; index++) {
		msg_exp_step(index, W);
	}

	/*
	 *	Compression Function
	 */
	for (int step = 0; step < 64; step++) {
		compression_step(step, W);

		/*
		 *	Uncomment the following line to print compression step information on console.
		 */
		// info_print(step);
	}

	/*
	 *	Following loop is used for XORing "IV" with "reg".
	 *	For our purpose, we can ignore the following loop.
	 *
	 *	NOTE 1:
	 *	Uncomment the following code for more formal implementation of SHA-256.
	 */
	// for (int i = 0; i < 8; i++){
	// 	IV[i] += reg[i];
	// }

	// for (int i = 0, j = 0; i < 8; i++) {
	// 	in_msg_hash_digest[j++] = (uint8_t) (IV[i] >> 24);
	// 	in_msg_hash_digest[j++] = (uint8_t) (IV[i] >> 16);
	// 	in_msg_hash_digest[j++] = (uint8_t) (IV[i] >> 8);
	// 	in_msg_hash_digest[j++] = (uint8_t) IV[i];
	// }

	for (int i = 0, j = 0; i < 8; i++) {
		in_msg_hash_digest[j++] = (uint8_t) (reg[i] >> 24);
		in_msg_hash_digest[j++] = (uint8_t) (reg[i] >> 16);
		in_msg_hash_digest[j++] = (uint8_t) (reg[i] >> 8);
		in_msg_hash_digest[j++] = (uint8_t) reg[i];
	}
	/*
	 *	Calculation of the Partial Hash Digest: "Completed".
	 *	The Partial Hash Digest is stored in "uint8_t" type variable named "in_msg_hash_digest".
	 */
	
	char in_msg_hash_digest_string[65];
	hash_digest_to_hash_string(in_msg_hash_digest_string, in_msg_hash_digest);

	printf("Input String:\t\t\t\t %s\n", in_msg);
	printf("Input String Hash Digest String:\t %s\n", in_msg_hash_digest_string);

	return 0;
}
