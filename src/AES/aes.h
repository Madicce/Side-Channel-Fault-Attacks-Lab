#include <stdint.h>

void aes_key_expansion(const uint8_t *key, uint8_t *round_keys);

void aes_encrypt(uint8_t *state, const uint8_t *round_keys);

void aes_decrypt(uint8_t *state, const uint8_t *round_keys);