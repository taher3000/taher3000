#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <omp.h>

#define PRIVATE_KEY_SIZE 32
#define ADDRESS "1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF"
#define REPORT_INTERVAL 100000 // Report progress every 100,000 keys
#define SLEEP_INTERVAL 100000 // Sleep every 100,000 keys (in microseconds)

unsigned char target_address_bytes[25];

// Xoshiro256** PRNG state (one per thread)
static __thread uint64_t s[4];

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t next(void) {
    const uint64_t result = rotl(s[1] * 5, 7) * 9;
    const uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45);
    return result;
}

static inline void generate_private_key(unsigned char *private_key) {
    for (int i = 0; i < PRIVATE_KEY_SIZE; i += 8) {
        uint64_t r = next();
        memcpy(private_key + i, &r, 8);
    }
    private_key[0] &= 0x7F;
}

void precompute_target_address() {
    static const char* base58_table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    memset(target_address_bytes, 0, 25);
    for (int i = 0; ADDRESS[i] != '\0'; i++) {
        const char* pos = strchr(base58_table, ADDRESS[i]);
        if (pos == NULL) continue;
        int index = pos - base58_table;
        for (int j = 24; j >= 0; j--) {
            int carry = target_address_bytes[j] * 58 + index;
            target_address_bytes[j] = carry;
            index = carry >> 8;
        }
    }
}

static inline bool check_private_key(const unsigned char* private_key, EC_GROUP* group, BN_CTX* ctx, EVP_MD_CTX* mdctx) {
    EC_POINT* pub_key_point = EC_POINT_new(group);
    BIGNUM* priv = BN_bin2bn(private_key, 32, NULL);
    
    EC_POINT_mul(group, pub_key_point, priv, NULL, NULL, ctx);

    unsigned char pub_key[65];
    size_t pub_len = EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED, pub_key, 65, ctx);

    unsigned char sha256[SHA256_DIGEST_LENGTH];
    SHA256(pub_key, pub_len, sha256);

    unsigned char ripemd160[EVP_MAX_MD_SIZE];
    unsigned int ripemd160_len;
    EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(mdctx, sha256, SHA256_DIGEST_LENGTH);
    EVP_DigestFinal_ex(mdctx, ripemd160, &ripemd160_len);

    unsigned char with_version[21] = {0x00};
    memcpy(with_version + 1, ripemd160, 20);

    SHA256(with_version, 21, sha256);
    SHA256(sha256, SHA256_DIGEST_LENGTH, sha256);

    bool match = (memcmp(with_version, target_address_bytes, 21) == 0 &&
                  memcmp(sha256, target_address_bytes + 21, 4) == 0);

    EC_POINT_free(pub_key_point);
    BN_free(priv);

    return match;
}

int main() {
    precompute_target_address();

    bool found_match = false;
    unsigned char private_key[PRIVATE_KEY_SIZE];
    char private_key_hex[65];

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    printf("Starting key generation and checking...\n");
    printf("Target address: %s\n", ADDRESS);

    uint64_t total_keys = 0;
    time_t start_time = time(NULL);

    #pragma omp parallel
    {
        // Initialize PRNG for each thread
        RAND_bytes((unsigned char*)s, sizeof(s));

        BN_CTX* ctx = BN_CTX_new();
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        uint64_t local_keys = 0;

        while (!found_match) {
            generate_private_key(private_key);

            if (check_private_key(private_key, group, ctx, mdctx)) {
                #pragma omp critical
                {
                    found_match = true;
                    for (int j = 0; j < PRIVATE_KEY_SIZE; j++) {
                        sprintf(private_key_hex + (2 * j), "%02x", private_key[j]);
                    }
                    printf("\nMatch found for key: %s\n", private_key_hex);
                }
            }

            local_keys++;

            if (local_keys % REPORT_INTERVAL == 0) {
                #pragma omp atomic
                total_keys += local_keys;

                #pragma omp single
                {
                    time_t current_time = time(NULL);
                    double elapsed_time = difftime(current_time, start_time);
                    double keys_per_second = total_keys / elapsed_time;

                    printf("\rKeys checked: %lu | Speed: %.2f keys/s", total_keys, keys_per_second);
                    fflush(stdout);
                }

                local_keys = 0;
                usleep(SLEEP_INTERVAL);  // Sleep to reduce CPU usage
            }

            #pragma omp cancellation point parallel
        }

        #pragma omp atomic
        total_keys += local_keys;

        BN_CTX_free(ctx);
        EVP_MD_CTX_free(mdctx);
    }

    EC_GROUP_free(group);

    if (!found_match) {
        printf("\nNo matching private key found for the given address.\n");
    }

    return 0;
}
