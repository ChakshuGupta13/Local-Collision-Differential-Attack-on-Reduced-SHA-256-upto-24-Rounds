#include <bits/stdc++.h>

#define WORD_SIZE 32U
#define ROTATE_RIGHT(x, n) ((x << n) | (x >> (WORD_SIZE - n)))
#define SMALL_SIGMA_1(x) ((ROTATE_RIGHT(x, 17U) ^ (ROTATE_RIGHT(x, 19U) ^ (x >> 10U))))
#define DEL(x) (SMALL_SIGMA_1(x) - SMALL_SIGMA_1((x - 1)))

using namespace std;

int main() {
    map<int, int> hash_map;

    unsigned int x = 0;
    for (unsigned int loop = 1; loop <= (1U << 16U); loop++)
        for (unsigned int num = 1; num <= (1U << 16U); num++) {
            hash_map[DEL(x)]++;
            x++;
        }
    int max = INT_MIN;
    for (auto element: hash_map)
        if (element.second > max)
            max = element.second;
    for (auto element: hash_map)
        if (element.second == max)
            printf("0x%08x\n", element.first);
}