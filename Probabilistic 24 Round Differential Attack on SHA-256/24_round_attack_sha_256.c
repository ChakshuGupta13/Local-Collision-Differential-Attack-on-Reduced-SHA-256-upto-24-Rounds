#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

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

static inline void init_reg(uint32_t * reg){
	reg[0] = 0x6a09e667;
	reg[1] = 0xbb67ae85;
	reg[2] = 0x3c6ef372;
	reg[3] = 0xa54ff53a;
	reg[4] = 0x510e527f;
	reg[5] = 0x9b05688c;
	reg[6] = 0x1f83d9ab;
	reg[7] = 0x5be0cd19;
}

void print_msg(int start_index, int last_index, uint32_t * W){
	for(int index = start_index; index <= last_index; index++){
		printf("0x%08x, ", W[index]);
		if((index + 1) % 8 == 0){
			printf("\n");
		}
	}
}

uint32_t gen_rand_32_bit(){ 
	uint32_t x;

	x = random() & 0xff;
	x |= (random() & 0xff) << 8;
	x |= (random() & 0xff) << 16;
	x |= (random() & 0xff) << 24;

	return x;
}

void compression_step(uint32_t * reg, int step, uint32_t * W){
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

static inline void compression_step_info_print(int step, uint32_t * reg){
	printf("Step %d:\n", step);
	printf("%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\t%08x\n", reg[0], reg[1], reg[2], reg[3], reg[4], reg[5], reg[6], reg[7]);
}

static inline uint32_t msg_exp(int index, uint32_t * W){
	return (W[index - 16] + sigma_0(W[index - 15]) + W[index - 7] + sigma_1(W[index - 2]));
}

static inline void W_from_a(uint32_t * reg, uint32_t * W, uint32_t * a, int step){
	W[step] = a[step] - (SIGMA_0(reg[0]) + MAJ(reg[0], reg[1], reg[2]) + reg[7] + SIGMA_1(reg[4]) + IF(reg[4], reg[5], reg[6]) + K[step]);
}

static inline uint32_t C_calc(int index, uint32_t * a, uint32_t * e){
	return (e[index + 5] - SIGMA_1(e[index + 4]) - IF(e[index + 4], e[index + 3], e[index + 2]) - 2*a[index + 1] - K[index + 5] + SIGMA_0(a[index]));
}

static inline void phi_calc(uint32_t * reg, uint32_t * phi, int index){
	phi[index] = SIGMA_0(reg[0]) + MAJ(reg[0], reg[1], reg[2]) + SIGMA_1(reg[4]) + IF(reg[4], reg[5], reg[6]) + reg[7] + K[index + 1];
}

void msg_exp_check(int start_step, int last_step, uint32_t * msg){

	if(start_step < 16){
		printf("Expansion not posssible from step %d.\n", start_step);
		return;
	}

	for(int step = start_step; step <= last_step; step++){
		if(msg_exp(step, msg) == msg[step]){
			printf("Message Expansion at %d: Correct! :)\n", step);
		} else {
			printf("\nMessage Expansion at %d: Incorrect! :(\n", step);
			printf("Message Word is:\t%08x\n", msg[step]);
			printf("Expected Word is:\t%08x\n\n", msg_exp(step, msg));
		}
	}

	return;
}

void collision_check(uint32_t * reg, uint32_t * reg_dash){
	int reg_same = 1;
	for(int reg_index = 0; reg_index < 8; reg_index++){
		if(reg[reg_index] == reg_dash[reg_index]){
			continue;
		} else {
			reg_same = 0;
			break;
		}
	}
	if(reg_same){
		printf("Colliding Message Pairs Confirmed! :)\n");
	} else {
		printf("Message Pairs not Colliding! :(\n");
	}

	return;
}

void msg_compression(int start_step, int last_step, uint32_t * reg, uint32_t * msg){
	for(int step = start_step; step <= last_step; step++){
		compression_step(reg, step, msg);
		
		// compression_step_info_print(reg);
	}
}

int main(){
	uint32_t W[24];
	uint32_t reg[8];

	init_reg(reg);

	uint32_t a[24];
	uint32_t e[24];
	uint32_t phi[24];
	uint32_t C[24];

	uint32_t u = 1;
	
	uint32_t del_1 = 0x00006000;
	uint32_t del_2 = 0xff006001;
	
	uint32_t alpha = 0x32b308b2;
	uint32_t lamda = 0x051f9f7f;
	uint32_t gamma = 0x98e3923b;
	uint32_t mu = 	 0xfbe05f81;

	a[8] = alpha;
	a[9] = alpha;
	a[10] = -1;
	a[11] = ~alpha;
	a[12] = ~alpha;

	e[8] = gamma;
	e[9] = gamma + 1;
	e[10] = -1;
	e[11] = mu;
	e[12] = lamda;
	e[13] = lamda - 1;
	e[14] = -1;
	e[15] = -1;
	e[16] = -1 - u;

	uint32_t del_W[24] = {0};
	del_W[10] = 1;
	del_W[11] = -1;
	del_W[12] = del_1;
	del_W[13] = del_2;
	del_W[14] = 0;
	del_W[15] = 0;
	del_W[16] = 0;
	del_W[17] = 1;
	del_W[18] = -1;

	srandom(time(NULL));
	long int start = clock();
	do{
		int W_1_found = 0;
		do{
			init_reg(reg);
			W[0] = gen_rand_32_bit();
			a[2] = gen_rand_32_bit();
			a[3] = gen_rand_32_bit();

			compression_step(reg, 0, W);
			a[0] = reg[0];
			e[0] = reg[4];
			phi_calc(reg, phi, 0);

			a[7] = e[11] - a[11] + SIGMA_0(a[10]) + MAJ(a[10], a[9], a[8]);
			a[6] = e[10] - a[10] + SIGMA_0(a[9]) + MAJ(a[9], a[8], a[7]);
			a[5] = e[9] - a[9] + SIGMA_0(a[8]) + MAJ(a[8], a[7], a[6]);
			a[4] = e[8] - a[8] + SIGMA_0(a[7]) + MAJ(a[7], a[6], a[5]);

			e[7] = a[7] + a[3] - SIGMA_0(a[6]) - MAJ(a[6], a[5], a[4]);
			e[6] = a[6] + a[2] - SIGMA_0(a[5]) - MAJ(a[5], a[4], a[3]);

			C[4] = C_calc(4, a, e);

			W[16] = e[16] - SIGMA_1(e[15]) - IF(e[15], e[14],e[13]) - a[12] - e[12] - K[16];
			W[14] = e[14] - SIGMA_1(e[13]) - IF(e[13], e[12],e[11]) - a[10] - e[10] - K[14];

			uint32_t D = (W[16] - (sigma_1(W[14]) + C[4] + MAJ(a[4], a[3], a[2]) - phi[0] + W[0]));

			for(uint32_t iterator = 0; iterator <= 0x00007fff; iterator++){
				W[1] = iterator;

				uint32_t X = D + W[1];
				uint32_t Y = (W[1] >> 3) ^ (W[1] >> 7);
				W[1] = W[1] | ROT_R(((X ^ Y)&(0xff)), 14);

				uint32_t W_1_25_18 = (X ^ Y)&(0xff);

				uint32_t temp = W[1];
				for(uint32_t c_0 = 0; c_0 < 2; c_0++){
					W[1] = temp;
					X = (D >> 19) + (W_1_25_18 >> 1) + c_0;
					Y = (W[1] >> 5) ^ (W_1_25_18 >> 4);
					W[1] = W[1] | ROT_R(((X ^ Y)&(0xf)), 6);

					uint32_t W_1_29_26 = (X ^ Y)&(0xf);

					uint32_t temp2 = W[1];
					for(uint32_t c_1 = 0; c_1 < 2; c_1++){
						W[1] = temp2;
						X = (D >> 23) + (W_1_25_18 >> 5) + c_1;
						Y = (W[1] >> 9) ^ (W_1_29_26);
						W[1] = W[1] | ROT_R(((X ^ Y)&(0x3)), 2);

						uint32_t temp3 = W[1];
						for(uint32_t c_2 = 0; c_2 < 2; c_2++){
							W[1] = temp3;
							X = (D >> 8) + (W[1] >> 8) + c_2;
							Y = (W[1] >> 11) ^ W_1_29_26;
							W[1] = W[1] | ROT_R(((X ^ Y)&(0x7)), 17);

							if(D == (sigma_0(W[1]) - W[1])){
								W_1_found = 1;
								break;
							}
						}
						if(W_1_found){
							break;
						}
					}
					if (W_1_found) {
						break;
					}
				}
				if (W_1_found) {
					break;
				}
				if(iterator == 0x00007fff){
					break;
				}
			}
		}while(!W_1_found);

		compression_step(reg, 1, W);
		a[1] = reg[0];
		e[1] = reg[4];
		phi_calc(reg, phi, 1);

		W_from_a(reg, W, a, 2);
		
		compression_step(reg, 2, W);
		a[2] = reg[0];
		e[2] = reg[4];
		phi_calc(reg, phi, 2);

		W_from_a(reg, W, a, 3);

		compression_step(reg, 3, W);
		a[3] = reg[0];
		e[3] = reg[4];

		W[15] = e[15] - SIGMA_1(e[14]) - IF(e[14], e[13],e[12]) - a[11] - e[11] - K[15];
		C[5] = C_calc(5, a, e);

		W[17] = sigma_1(W[15]) + C[5] - W[2] + MAJ(a[5], a[4], a[3]) - phi[1] + sigma_0(W[2]) + W[1];

		C[6] = C_calc(6, a, e);
		W[18] = sigma_1(W[16]) + C[6] - W[3] + MAJ(a[6], a[5], a[4]) - phi[2] + sigma_0(W[3]) + W[2];
	}while(((sigma_1(W[17] + 1) - sigma_1(W[17])) != (-del_1)) || ((sigma_1(W[18] - 1) - sigma_1(W[18])) != (-del_2)));

	printf("Avg. Clocks consumed:\t%lu\n", clock() - start);
	printf("Clocks per second:\t%lu\n\n", CLOCKS_PER_SEC);

	printf("W[17] & W[18] Found! :)\n\n");
	
	for(int index = 4; index < 13; index++){
		W_from_a(reg, W, a, index);
		compression_step(reg, index, W);
		
		// compression_step_info_print(reg);
	}

	W[13] = e[13] - SIGMA_1(e[12]) - IF(e[12], e[11], e[10]) - a[9] - e[9] - K[13];
	msg_compression(13, 15, reg, W);

	printf("Message Expansion Correctness Checking for W:\n");
	msg_exp_check(16, 18, W);
	printf("\n");

	for(int i = 19; i < 24; i++){
		W[i] = msg_exp(i, W);
	}

	msg_compression(16, 23, reg, W);

	print_msg(0, 23, W);

	/*
	 *	Generation of Colliding Message:  W_dash
	 */
	uint32_t W_dash[24];

	uint32_t reg_dash[8];
	init_reg(reg_dash);

	for(int i = 0; i < 24; i++){
		W_dash[i] = W[i] + del_W[i];
	}

	printf("W_dash:\n");
	print_msg(0, 23, W_dash);
	printf("\n");

	printf("Message Expansion Correctness Checking for W_dash:\n");
	msg_exp_check(16, 23, W_dash);
	printf("\n");

	msg_compression(0, 23, reg_dash, W_dash);

	/*
	 *	Collision Confirmation
	 */
	collision_check(reg, reg_dash);
}