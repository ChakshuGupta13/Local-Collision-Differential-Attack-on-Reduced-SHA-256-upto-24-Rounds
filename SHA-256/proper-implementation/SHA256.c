#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHUNK_SIZE 64
#define TOTAL_LEN_LEN 8
#define ITERATIONS 1000

/*
 * Initialize Array of 64 Round Constants (each of 32 bits):
 * 		First 32 bits of
 *		Fractional parts of
 *		Cube Roots of
 *		First 64 primes: 2..311
 */
const uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

struct buffer_state
{
	const uint8_t *p;
	size_t len;
	size_t total_len;
	int is_single_padding_bit_1_padded;
	int is_complete_input_string_chunked;
};

static inline uint32_t right_rotation(uint32_t value, unsigned int count)
{
	return value >> count | value << (32 - count);
}

void init_buf_state(struct buffer_state *state, const void *input, size_t len)
{
	state->p = input;
	state->len = len;
	state->total_len = len;
	state->is_single_padding_bit_1_padded = 0;
	state->is_complete_input_string_chunked = 0;
}

int calc_chunk(uint8_t chunk[CHUNK_SIZE], struct buffer_state *state)
{
	size_t space_in_chunk;

	if (state->is_complete_input_string_chunked)
	{
		return 0;
	}

	if (state->len >= CHUNK_SIZE)
	{
		memcpy(chunk, state->p, CHUNK_SIZE);
		state->p += CHUNK_SIZE;
		state->len -= CHUNK_SIZE;
		return 1;
	}

	memcpy(chunk, state->p, state->len);
	chunk += state->len;
	space_in_chunk = CHUNK_SIZE - state->len;
	state->p += state->len;
	state->len = 0;

	if (!state->is_single_padding_bit_1_padded)
	{
		*chunk++ = 0x80;
		space_in_chunk -= 1;
		state->is_single_padding_bit_1_padded = 1;
	}

	if (space_in_chunk >= TOTAL_LEN_LEN)
	{
		const size_t left = space_in_chunk - TOTAL_LEN_LEN;
		size_t len = state->total_len;
		int i;
		memset(chunk, 0x00, left);
		chunk += left;

		/* Storing of len * 8 as a big endian 64-bit without overflow. */
		chunk[7] = (uint8_t)(len << 3);
		len >>= 5;
		for (i = 6; i >= 0; i--)
		{
			chunk[i] = (uint8_t)len;
			len >>= 8;
		}
		state->is_complete_input_string_chunked = 1;
	}
	else
	{
		memset(chunk, 0x00, space_in_chunk);
	}

	return 1;
}

/*
 * Limitations:
 * - Since input is a pointer in RAM, the data to hash should be in RAM, which could be a problem
 *   for large data sizes.
 * - SHA algorithms theoretically operate on bit strings. However, this implementation has no support
 *   for bit string lengths that are not multiples of eight, and it really operates on arrays of bytes.
 *   In particular, the len parameter is a number of bytes.
 */
void calc_sha_256(uint8_t hash[32], const void *input, size_t len)
{
	/*
	 * Note 1: All integers (expect indexes) are 32-bit unsigned integers and addition is calculated modulo 2^32.
	 * Note 2: For each round, there is one round constant K[i] and one entry in the message schedule array W[i], 0 = i = 63
	 * Note 3: The compression function uses 8 working variables, a through h
	 * Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
	 *     and when parsing message block data from bytes to words, for example,
	 *     the first word of the input message "abc" after padding is 0x61626380
	 */

	/*
	 * Initialize Hash Values:
	 * 		First 32 bits of
	 *		Fractional parts of 
	 *		Square roots of
	 *		First 8 primes: 2..19
	 */
	uint32_t h[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	int i, j;

	/* 
	 *	Chunk Size:			512-bits
	 *	Words in a Chunk:	64
	 *	word Size:			8-bits
	 */
	uint8_t chunk[64];

	struct buffer_state state;
	init_buf_state(&state, input, len);

	while (calc_chunk(chunk, &state))
	{
		uint32_t registers[8];
		uint32_t W[64];
		const uint8_t *p = chunk;

		memset(W, 0x00, sizeof W);
		for (i = 0; i < 16; i++)
		{
			W[i] = (uint32_t)p[0] << 24 |
				   (uint32_t)p[1] << 16 |
				   (uint32_t)p[2] << 8 |
				   (uint32_t)p[3];
			p += 4;
		}

		/*
		 *	Message Expansion Step
		 */
		for (i = 16; i < 64; i++)
		{
			const uint32_t Sigma_0 = right_rotation(W[i - 15], 7) ^ right_rotation(W[i - 15], 18) ^ (W[i - 15] >> 3);
			const uint32_t Sigma_1 = right_rotation(W[i - 2], 17) ^ right_rotation(W[i - 2], 19) ^ (W[i - 2] >> 10);

			W[i] = W[i - 16] + Sigma_0 + W[i - 7] + Sigma_1;
		}

		/* 
		 *	Initialize 
		 *	Registers to
		 *	Current Hash Value
		 */
		for (i = 0; i < 8; i++)
		{
			registers[i] = h[i];
		}

		/*
		 *	Compression Function 
		 */
		for (i = 0; i < 64; i++)
		{
			const uint32_t Sigma_0 = right_rotation(registers[0], 2) ^ right_rotation(registers[0], 13) ^ right_rotation(registers[0], 22);
			const uint32_t Sigma_1 = right_rotation(registers[4], 6) ^ right_rotation(registers[4], 11) ^ right_rotation(registers[4], 25);

			const uint32_t function_IF = (registers[4] & registers[5]) ^ (~registers[4] & registers[6]);
			const uint32_t function_MAJ = (registers[0] & registers[1]) ^ (registers[0] & registers[2]) ^ (registers[1] & registers[2]);

			const uint32_t temp1 = registers[7] + Sigma_1 + function_IF + K[i] + W[i];
			const uint32_t temp2 = Sigma_0 + function_MAJ;

			registers[7] = registers[6];
			registers[6] = registers[5];
			registers[5] = registers[4];
			registers[4] = registers[3] + temp1;
			registers[3] = registers[2];
			registers[2] = registers[1];
			registers[1] = registers[0];
			registers[0] = temp1 + temp2;
		}

		/* 	
		 *	Add
		 *	Compressed Chunk to 
		 *	Current Hash Value
		 */
		for (i = 0; i < 8; i++)
		{
			h[i] += registers[i];
		}
	}

	/*
	 *	Produce the Final Hash Value (Big-Endian)
	 */
	for (i = 0, j = 0; i < 8; i++)
	{
		hash[j++] = (uint8_t)(h[i] >> 24);
		hash[j++] = (uint8_t)(h[i] >> 16);
		hash[j++] = (uint8_t)(h[i] >> 8);
		hash[j++] = (uint8_t)h[i];
	}
}

void hash_digest_to_hash_string(char *input_string_hash_digest_string,
								const uint8_t input_string_hash_digest[32])
{
	for (size_t byte_index = 0; byte_index < 32; byte_index++)
	{
		input_string_hash_digest_string +=
			sprintf(input_string_hash_digest_string, "%02x", input_string_hash_digest[byte_index]);
	}
}

int main(int argc, char **argv)
{
	clock_t start_time, end_time;

	/*
	 *	Extracting Input String
	 */
	char *input_string = (char *)malloc(sizeof(char) * strlen(argv[1]));
	for (int index = 0; index < strlen(argv[1]); index++)
	{
		input_string[index] = argv[1][index];
	}
	for (unsigned int i = 2; i <= argc - 1; ++i)
	{
		strcat(input_string, " ");
		strcat(input_string, argv[i]);
	}

	/*
	 *	Computing Hash Digest of Input String
	 */
	uint8_t input_string_hash_digest[32];
	unsigned long long int total_cycles = 0;

	for (int iteration = 0; iteration < ITERATIONS; ++iteration)
	{
		start_time = clock();

		calc_sha_256(input_string_hash_digest, input_string, strlen(input_string));

		end_time = clock();

		total_cycles += (end_time - start_time);
	}

	/*
	 *	Converting Hexadecimal Hash Digest -> String Hash Digest
	 */
	char input_string_hash_digest_string[65];
	hash_digest_to_hash_string(input_string_hash_digest_string, input_string_hash_digest);

	/*
	 *	Printing:
	 *		Input String
	 *		and
	 *		Input String's Hash Digest String
	 */
	printf("Input String:\t\t\t\t %s\n", input_string);
	printf("Input String Hash Digest String:\t %s\n", input_string_hash_digest_string);

	printf("Clocks consumed (average) while Hashing: %f\n", (double)total_cycles / ITERATIONS);
	return 0;
}
