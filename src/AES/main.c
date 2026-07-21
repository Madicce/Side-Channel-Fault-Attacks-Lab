#include "aes.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LENGTH 16

void aes_encrypt_init(uint8_t *plaintext, uint8_t *key) {
  uint8_t round_keys[176];
  aes_key_expansion(key, round_keys);
  aes_encrypt(plaintext, round_keys);
}

void aes_decrypt_init(uint8_t *ciphertext, uint8_t *key) {
  uint8_t round_keys[176];
  aes_key_expansion(key, round_keys);
  aes_decrypt(ciphertext, round_keys);
}

int main(int argc, char *argv[]) {
  // uint8_t plaintext[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  //                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  // // srand(time(NULL));

  // // uint8_t plaintext[] = {
  // //     rand() & 0xff, rand() & 0xff, rand() & 0xff, rand() & 0xff, rand() &
  // //     0xff, rand() & 0xff, rand() & 0xff, rand() & 0xff, rand() & 0xff,
  // //     rand() & 0xff, rand() & 0xff, rand() & 0xff, rand() & 0xff, rand() &
  // //     0xff, rand() & 0xff, rand() & 0xff, rand() & 0xff, rand() & 0xff};
  // uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  //                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  // for (int i = 0; i < 16; i++) {
  //   printf("%02x", plaintext[i]);
  // }
  // printf("\n");

  // aes_encrypt_init(plaintext, key);

  // for (int i = 0; i < 16; i++) {
  //   printf("%02x", plaintext[i]);
  // }
  // printf("\n");
}