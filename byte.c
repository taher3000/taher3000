#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define ADDRESS_SIZE 35

void sha256(unsigned char *input, size_t length, unsigned char *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, length);
    SHA256_Final(output, &sha256);
}

void ripemd160(unsigned char *input, size_t length, unsigned char *output) {
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, input, length);
    RIPEMD160_Final(output, &ripemd160);
}

void hash160(unsigned char *input, size_t length, unsigned char *output) {
    unsigned char sha256_result[SHA256_DIGEST_LENGTH];
    sha256(input, length, sha256_result);
    ripemd160(sha256_result, SHA256_DIGEST_LENGTH, output);
}

const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void base58_encode(unsigned char *input, size_t length, char *output) {
    BIGNUM *bn = BN_new();
    BN_bin2bn(input, length, bn);
    
    char reverse_output[ADDRESS_SIZE];
    int i = 0;
    while (!BN_is_zero(bn)) {
        BN_ULONG rem = BN_div_word(bn, 58);
        reverse_output[i++] = base58_chars[rem];
    }
    
    for (int j = 0; j < length && input[j] == 0; j++) {
        reverse_output[i++] = base58_chars[0];
    }
    
    for (int j = 0; j < i; j++) {
        output[j] = reverse_output[i - 1 - j];
    }
    output[i] = '\0';
    
    BN_free(bn);
}

int check_private_key(const char *address, const char *private_key_hex) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv = BN_new();
    BN_hex2bn(&priv, private_key_hex);
    EC_KEY_set_private_key(key, priv);
    
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, NULL);
    EC_KEY_set_public_key(key, pub);
    
    unsigned char pub_bytes[65];
    size_t pub_len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_bytes, 65, NULL);
    
    unsigned char hash160_result[20];
    hash160(pub_bytes, pub_len, hash160_result);
    
    unsigned char address_bytes[25] = {0};
    address_bytes[0] = 0x00;  // Mainnet address
    memcpy(address_bytes + 1, hash160_result, 20);
    
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    sha256(address_bytes, 21, checksum);
    sha256(checksum, SHA256_DIGEST_LENGTH, checksum);
    memcpy(address_bytes + 21, checksum, 4);
    
    char calculated_address[ADDRESS_SIZE];
    base58_encode(address_bytes, 25, calculated_address);
    
    int result = strcmp(address, calculated_address) == 0;
    
    EC_KEY_free(key);
    BN_free(priv);
    EC_POINT_free(pub);
    
    return result;
}

void benchmark(int num_checks) {
    const char *address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    const char *private_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    
    printf("Starting benchmark...\n");
    
    clock_t start = clock();
    
    for (int i = 0; i < num_checks; i++) {
        check_private_key(address, private_key_hex);
    }
    
    clock_t end = clock();
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    
    printf("Benchmark complete.\n");
    printf("Performed %d checks in %.4f seconds\n", num_checks, cpu_time_used);
    printf("Average time per check: %.2f microseconds\n", (cpu_time_used * 1000000) / num_checks);
}

int main() {
    const char *address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    const char *private_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    
    int result = check_private_key(address, private_key_hex);
    printf("The private key %s the given Bitcoin address.\n", result ? "matches" : "does not match");
    
    printf("Running benchmark...\n");
    benchmark(1000000);
    printf("Program complete.\n");
    
    return 0;
}
