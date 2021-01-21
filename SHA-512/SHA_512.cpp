#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <iomanip>
#include <sstream>

#define BLOCK_SIZE_in_BITS 1024
#define BYTE_SIZE_in_BITS 8
#define BLOCK_SIZE_in_BYTES (BLOCK_SIZE_in_BITS / BYTE_SIZE_in_BITS)
#define MSG_LEN_SIZE_in_BITS 128
#define WORD_SIZE_in_BITS 64
#define NUM_SHA_STEPS 80
#define HASH_SIZE_in_BITS 512
#define NUM_REG 8

using namespace std;

typedef bitset<BLOCK_SIZE_in_BITS> BLOCK;
typedef bitset<BYTE_SIZE_in_BITS> BYTE;
typedef bitset<WORD_SIZE_in_BITS> WORD;
typedef bitset<HASH_SIZE_in_BITS> HASH;

const uint_fast64_t K[] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
                           0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
                           0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                           0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                           0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
                           0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                           0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
                           0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                           0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                           0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                           0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
                           0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                           0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
                           0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                           0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                           0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

inline WORD right_shift(WORD word, int num_bits)
{
    return (word >> num_bits);
}

inline WORD right_rotate(WORD word, int num_bits)
{
    return ((word >> num_bits) | (word << (WORD_SIZE_in_BITS - num_bits)));
}

inline uint_fast64_t sigma_0(WORD word)
{
    return (right_rotate(word, 1) ^ right_rotate(word, 8) ^ right_shift(word, 7)).to_ullong();
}

inline uint_fast64_t sigma_1(WORD word)
{
    return (right_rotate(word, 19) ^ right_rotate(word, 61) ^ right_shift(word, 6)).to_ullong();
}

inline uint_fast64_t Sigma_0(WORD word)
{
    return (right_rotate(word, 28) ^ right_rotate(word, 34) ^ right_rotate(word, 39)).to_ullong();
}

inline uint_fast64_t Sigma_1(WORD word)
{
    return (right_rotate(word, 14) ^ right_rotate(word, 18) ^ right_rotate(word, 41)).to_ullong();
}

inline uint_fast64_t CH(WORD x, WORD y, WORD z)
{
    return ((x & y) ^ (~x & z)).to_ullong();
}

inline uint_fast64_t MAJ(WORD x, WORD y, WORD z)
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

void print_reg(vector<WORD> reg)
{
    for (int i = 0; i < (NUM_REG / 2); i++)
        cout << hex << reg[i].to_ullong() << " ";
    cout << "\n";
    for (int i = (NUM_REG / 2); i < NUM_REG; i++)
        cout << hex << reg[i].to_ullong() << " ";
    cout << "\n";
}

void compress(const vector<WORD> &W, vector<WORD> &H)
{
    vector<WORD> R = H;
    for (int i = 0; i < NUM_SHA_STEPS; i++)
    {
        uint_fast64_t T1 = R[7].to_ullong() + Sigma_1(R[4]) + CH(R[4], R[5], R[6]) + K[i] + W[i].to_ullong();
        uint_fast64_t T2 = Sigma_0(R[0]) + MAJ(R[0], R[1], R[2]);
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

string SHA512(string msg)
{
    vector<BLOCK> msg_blocks = pre_process_phase_1(msg);
    vector<WORD> reg = {
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
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
    cout << SHA512(m) << "\n";
}