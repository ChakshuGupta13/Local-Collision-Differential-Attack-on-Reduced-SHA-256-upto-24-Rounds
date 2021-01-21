#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <iomanip>
#include <sstream>

#define BLOCK_SIZE_in_BITS 512
#define BYTE_SIZE_in_BITS 8
#define BLOCK_SIZE_in_BYTES (BLOCK_SIZE_in_BITS / BYTE_SIZE_in_BITS)
#define MSG_LEN_SIZE_in_BITS 64
#define WORD_SIZE_in_BITS 32
#define NUM_SHA_STEPS 64
#define HASH_SIZE_in_BITS 256
#define NUM_REG 8

using namespace std;

typedef bitset<BLOCK_SIZE_in_BITS> BLOCK;
typedef bitset<BYTE_SIZE_in_BITS> BYTE;
typedef bitset<WORD_SIZE_in_BITS> WORD;
typedef bitset<HASH_SIZE_in_BITS> HASH;

const uint_fast32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline WORD right_shift(WORD word, int num_bits)
{
    return (word >> num_bits);
}

inline WORD right_rotate(WORD word, int num_bits)
{
    return ((word >> num_bits) | (word << (WORD_SIZE_in_BITS - num_bits)));
}

inline uint_fast32_t sigma_0(WORD word)
{
    return (right_rotate(word, 7) ^ right_rotate(word, 18) ^ right_shift(word, 3)).to_ullong();
}

inline uint_fast32_t sigma_1(WORD word)
{
    return (right_rotate(word, 17) ^ right_rotate(word, 19) ^ right_shift(word, 10)).to_ullong();
}

inline uint_fast32_t Sigma_0(WORD word)
{
    return (right_rotate(word, 2) ^ right_rotate(word, 13) ^ right_rotate(word, 22)).to_ullong();
}

inline uint_fast32_t Sigma_1(WORD word)
{
    return (right_rotate(word, 6) ^ right_rotate(word, 11) ^ right_rotate(word, 25)).to_ullong();
}

inline uint_fast32_t CH(WORD x, WORD y, WORD z)
{
    return ((x & y) ^ (~x & z)).to_ullong();
}

inline uint_fast32_t MAJ(WORD x, WORD y, WORD z)
{
    return ((x & y) ^ (x & z) ^ (y & z)).to_ullong();
}

void expand(vector<WORD> &W)
{
    for (int i = (BLOCK_SIZE_in_BITS / WORD_SIZE_in_BITS); i < NUM_SHA_STEPS; i++)
        W[i] = sigma_1(W[i - 2]) + W[i - 7].to_ullong() + sigma_0(W[i - 15]) + W[i - 16].to_ullong();
}

vector<BLOCK> pre_process_phase_1(string m)
{
    size_t l = m.length();
    size_t l_in_bits = l * BYTE_SIZE_in_BITS;

    vector<BLOCK> M;
    size_t m_ind = 0;
    while ((l - m_ind) >= BLOCK_SIZE_in_BYTES)
    {
        BLOCK M_i = 0;
        string m_i = m.substr(m_ind, BLOCK_SIZE_in_BYTES);
        /*
        [Explaination]
        Instead of copying all 512 bits or 64 characters into @M_i block at once,
        copied character by character or 8 bits (@ch) at once.
        To avoid @M_i block get Little Endian encoded.
        */
        for (auto ch : m_i)
        {
            /*
            [Explanation]
            Right-shift @M_i block by 8-bits, to free its 8 LSB bits.
            Then copied the 8-bits character representation of @ch into those free 8 LSB bits.
            */
            M_i <<= BYTE_SIZE_in_BITS;
            M_i |= BLOCK(ch);
        }
        M.emplace_back(M_i);
        m_ind += BLOCK_SIZE_in_BYTES;
    }
    if (m_ind < l)
    {
        BLOCK M_i = 0;
        size_t num_char_left = l - m_ind;
        string m_i = m.substr(m_ind, num_char_left);
        int M_i_ind = (BLOCK_SIZE_in_BITS - 1);
        for (auto ch : m_i)
        {
            BYTE ch_in_byte(ch);
            for (int ch_in_byte_ind = (BYTE_SIZE_in_BITS - 1); ch_in_byte_ind >= 0; ch_in_byte_ind--)
                M_i[M_i_ind--] = ch_in_byte[ch_in_byte_ind];
        }
        M_i[M_i_ind--] = 1;
        if (M_i_ind >= (MSG_LEN_SIZE_in_BITS - 1))
        {
            M_i |= BLOCK(l_in_bits);
            M.emplace_back(M_i);
        }
        else
        {
            M.emplace_back(M_i);
            M.emplace_back(BLOCK(l_in_bits));
        }
    }
    else
    {
        BLOCK M_i(l_in_bits);
        M_i[BLOCK_SIZE_in_BITS - 1] = 1;
        M.emplace_back(M_i);
    }
    return M;
}

vector<WORD> pre_process_phase_2(BLOCK msg_block)
{
    vector<WORD> W(NUM_SHA_STEPS);
    BLOCK mask = 0xFFFFFFFFFFFFFFFF;
    for (int i = ((BLOCK_SIZE_in_BITS / WORD_SIZE_in_BITS) - 1); i >= 0; i--)
    {
        W[i] = WORD((msg_block & mask).to_ullong());
        msg_block >>= WORD_SIZE_in_BITS;
    }
    return W;
}

void compress(const vector<WORD> &W, vector<WORD> &H)
{
    vector<WORD> R = H;
    for (int i = 0; i < NUM_SHA_STEPS; i++)
    {
        uint_fast32_t T1 = R[7].to_ullong() + Sigma_1(R[4]) + CH(R[4], R[5], R[6]) + K[i] + W[i].to_ullong();
        uint_fast32_t T2 = Sigma_0(R[0]) + MAJ(R[0], R[1], R[2]);
        R[7] = R[6];
        R[6] = R[5];
        R[5] = R[4];
        R[4] = R[3].to_ullong() + T1;
        R[3] = R[2];
        R[2] = R[1];
        R[1] = R[0];
        R[0] = T1 + T2;
    }
    for (int i = 0; i < NUM_REG; i++)
        H[i] = H[i].to_ullong() + R[i].to_ullong();
}

string getHashDigest(const vector<WORD> &reg)
{
    HASH bin_hash_digest = 0;
    for (int reg_ind = 0; reg_ind < NUM_REG; reg_ind++)
    {
        bin_hash_digest <<= WORD_SIZE_in_BITS;
        bin_hash_digest |= HASH(reg[reg_ind].to_ullong());
    }
    int bin_hash_digest_ind = HASH_SIZE_in_BITS - 1;
    stringstream hex_hash_digest;
    for (int byte_ind = 0; byte_ind < (HASH_SIZE_in_BITS / BYTE_SIZE_in_BITS); byte_ind++)
    {
        BYTE byte = 0;
        for (int bit_ind = BYTE_SIZE_in_BITS - 1; bit_ind >= 0; bit_ind--)
            byte[bit_ind] = bin_hash_digest[bin_hash_digest_ind--];
        hex_hash_digest << setfill('0') << setw(2) << hex << uppercase << byte.to_ullong();
    }
    return hex_hash_digest.str();
}

string SHA256(string msg)
{
    vector<BLOCK> msg_blocks = pre_process_phase_1(msg);
    vector<WORD> reg = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (auto msg_block : msg_blocks)
    {
        vector<WORD> W = pre_process_phase_2(msg_block);
        expand(W);
        compress(W, reg);
    }
    return getHashDigest(reg);
}

int main()
{
    string m;
    getline(cin, m);
    cout << SHA256(m) << "\n";
}