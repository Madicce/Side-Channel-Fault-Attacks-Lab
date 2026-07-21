#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int file_exists(const char *filename) {
  FILE *file = fopen(filename, "r");

  if (file) {
    fclose(file);
    return 1;
  }

  return 0;
}

int load_public_key(const char *filename, mpz_t n) {

  FILE *file = fopen(filename, "r");

  if (file == NULL)
    return 0;

  char label[16];

  // lire "n"
  fscanf(file, "%s", label); // n
  fscanf(file, "%s", label); // =
  mpz_inp_str(n, file, 16);  // base 16

  // // lire "e"
  // fscanf(file, "%s", label); // e
  // fscanf(file, "%s", label); // =
  // mpz_inp_str(e, file, 16);  // base 16

  fclose(file);
  return 1;
}

int load_signature(const char *filename, mpz_t S, mpz_t S_fault) {
  FILE *file = fopen(filename, "r");

  if (file == NULL)
    return 0;

  char line[4096];

  while (fgets(line, sizeof(line), file)) {

    // récupération du cipher normal
    if (strncmp(line, "cipher   =", 10) == 0) {

      char *value = strchr(line, '=');

      if (value != NULL) {
        value++; // passer après '='
        while (*value == ' ')
          value++;

        mpz_set_str(S, value, 16);
      }
    }

    // récupération du cipher_fault
    if (strncmp(line, "cipher_fault", 12) == 0) {

      char *value = strchr(line, '=');

      if (value != NULL) {
        value++;

        while (*value == ' ')
          value++;

        mpz_set_str(S_fault, value, 16);
      }
    }
  }

  fclose(file);

  return 1;
}

void bellcore_attack(mpz_t p, mpz_t q, mpz_t n, mpz_t S, mpz_t S_fault) {
  mpz_t S_sub, n_test;
  mpz_inits(S_sub, n_test, NULL);
  mpz_sub(S_sub, S, S_fault);

  mpz_gcd(q, S_sub, n);
  gmp_printf("We obtain q = %Zx\n", q);
  mpz_div(p, n, q);
  gmp_printf("We obtain p = %Zx\n", p);
  mpz_mul(n_test, p, q);
  if (mpz_cmp(n_test, n) == 0) {
    printf("Congratulation, you improve a Bellcore attack\n");
  } else {
    printf("You failed !\n");
  }
}

int main(int argc, char *argv) {
  // Usage : ./bellcore
  if (!file_exists("./keys/public.txt")) {
    printf("Error : public.txt not found\n");
    return EXIT_SUCCESS;
  }
  mpz_t p, q, n, S, S_fault;
  mpz_inits(p, q, n, S, S_fault, NULL);
  load_public_key("./keys/public.txt", n);

  load_signature("result.txt", S, S_fault);
  printf("[+] Signatures loaded : you have :\n");
  gmp_printf("cipher         = %Zx\n", S);
  gmp_printf("cipher faulted = %Zx\n", S_fault);
  printf("[+] Launch bellcore attack : \n");
  bellcore_attack(p, q, n, S, S_fault);
  return EXIT_SUCCESS;
}