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

void inject_random_bit_fault(mpz_t x) {
  gmp_randstate_t state;

  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));
  mp_bitcnt_t bit;

  bit = gmp_urandomm_ui(state, mpz_sizeinbase(x, 2));

  mpz_combit(x, bit);
}

void generate_prime(mpz_t p, gmp_randstate_t state, int bits) {
  mpz_urandomb(p, state, bits);
  mpz_nextprime(p, p);
}

void save_public_key(const char *filename, mpz_t n, mpz_t e) {

  FILE *file = fopen(filename, "w");

  if (file == NULL) {
    perror("Erreur ouverture fichier");
    exit(EXIT_FAILURE);
  }

  fprintf(file, "n = ");
  mpz_out_str(file, 16, n);

  fprintf(file, "\n");

  fprintf(file, "e = ");
  mpz_out_str(file, 16, e);

  fprintf(file, "\n");

  fclose(file);
}

void save_private_key(const char *filename, mpz_t p, mpz_t q, mpz_t dp,
                      mpz_t dq, mpz_t qinv) {

  FILE *file = fopen(filename, "w");

  if (file == NULL) {
    perror("Erreur ouverture fichier");
    exit(EXIT_FAILURE);
  }

  fprintf(file, "p = ");
  mpz_out_str(file, 16, p);

  fprintf(file, "\n");

  fprintf(file, "q = ");
  mpz_out_str(file, 16, q);

  fprintf(file, "\n");

  fprintf(file, "dp = ");
  mpz_out_str(file, 16, dp);

  fprintf(file, "\n");

  fprintf(file, "dq = ");
  mpz_out_str(file, 16, dq);

  fprintf(file, "\n");

  fprintf(file, "qinv = ");
  mpz_out_str(file, 16, qinv);

  fprintf(file, "\n");

  fclose(file);
}

int load_public_key(const char *filename, mpz_t n, mpz_t e) {

  FILE *file = fopen(filename, "r");

  if (file == NULL)
    return 0;

  char label[16];

  // lire "n"
  fscanf(file, "%s", label); // n
  fscanf(file, "%s", label); // =
  mpz_inp_str(n, file, 16);  // base 16

  // lire "e"
  fscanf(file, "%s", label); // e
  fscanf(file, "%s", label); // =
  mpz_inp_str(e, file, 16);  // base 16

  fclose(file);
  return 1;
}

int load_private_key(const char *filename, mpz_t p, mpz_t q, mpz_t dp, mpz_t dq,
                     mpz_t qinv) {

  FILE *file = fopen(filename, "r");

  if (file == NULL)
    return 0;

  char label[16];

  // lire "n"
  fscanf(file, "%s", label); // n
  fscanf(file, "%s", label); // =
  mpz_inp_str(p, file, 16);  // base 16

  // lire "e"
  fscanf(file, "%s", label); // e
  fscanf(file, "%s", label); // =
  mpz_inp_str(q, file, 16);  // base 16

  // lire "n"
  fscanf(file, "%s", label); // n
  fscanf(file, "%s", label); // =
  mpz_inp_str(dp, file, 16); // base 16

  // lire "e"
  fscanf(file, "%s", label); // e
  fscanf(file, "%s", label); // =
  mpz_inp_str(dq, file, 16); // base 16

  fscanf(file, "%s", label);   // e
  fscanf(file, "%s", label);   // =
  mpz_inp_str(qinv, file, 16); // base 16

  fclose(file);
  return 1;
}

void rsa_keygen(int bits) {

  mpz_t p, q, n, phi;
  mpz_t e, d;
  mpz_t dp, dq, qinv;
  mpz_t tmp1, tmp2;

  mpz_inits(p, q, n, phi, e, d, dp, dq, qinv, tmp1, tmp2, NULL);

  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));

  int half = bits / 2;

  // Génération p et q
  generate_prime(p, state, half);
  generate_prime(q, state, half);

  // n = p*q
  mpz_mul(n, p, q);

  // phi(n)
  mpz_sub_ui(tmp1, p, 1);
  mpz_sub_ui(tmp2, q, 1);
  mpz_mul(phi, tmp1, tmp2);

  // e = 65537
  mpz_set_ui(e, 65537);

  // d = e^-1 mod phi
  if (mpz_invert(d, e, phi) == 0) {
    printf("Erreur inverse impossible\n");
    return;
  }

  /*
      Paramètres CRT
  */

  // dp = d mod (p-1)
  mpz_sub_ui(tmp1, p, 1);
  mpz_mod(dp, d, tmp1);

  // dq = d mod (q-1)
  mpz_sub_ui(tmp2, q, 1);
  mpz_mod(dq, d, tmp2);

  // qinv = q^-1 mod p
  if (mpz_invert(qinv, q, p) == 0) {
    printf("Erreur inverse q^-1 impossible\n");
    return;
  }

  // printf("===== Cle RSA =====\n");

  // gmp_printf("n  = %Zx\n", n);
  // gmp_printf("e  = %Zd\n", e);

  // printf("\n===== Parametres CRT =====\n");

  // gmp_printf("p    = %Zx\n", p);
  // gmp_printf("q    = %Zx\n", q);
  // gmp_printf("dp   = %Zx\n", dp);
  // gmp_printf("dq   = %Zx\n", dq);
  // gmp_printf("qinv = %Zx\n", qinv);

  save_public_key("./keys/public.txt", n, e);
  save_private_key("./keys/private.txt", p, q, dp, dq, qinv);

  mpz_clears(p, q, n, phi, e, d, dp, dq, qinv, tmp1, tmp2, NULL);

  gmp_randclear(state);
}

// Chiffrement RSA avec CRT (inutile en pratique mais possible)
void encrypt_crt(mpz_t c, mpz_t m, mpz_t p, mpz_t q, mpz_t e, mpz_t qinv) {

  mpz_t Sp, Sq, h;

  mpz_inits(Sp, Sq, h, NULL);

  // Sp = m^e mod p
  mpz_powm(Sp, m, e, p);

  // Sq = m^e mod q
  mpz_powm(Sq, m, e, q);

  /* ------------- FAULT INJECTION HERE ------------- */
  inject_random_bit_fault(Sq);

  /*
      h = qinv*(Sp-Sq) mod p
  */
  mpz_sub(h, Sp, Sq);

  mpz_mul(h, h, qinv);

  mpz_mod(h, h, p);

  /*
      c = Sq + h*q
  */
  mpz_mul(h, h, q);

  mpz_add(c, Sq, h);

  mpz_clears(Sp, Sq, h, NULL);
}

// Déchiffrement RSA avec CRT
void decrypt_crt(mpz_t m, mpz_t c, mpz_t p, mpz_t q, mpz_t dp, mpz_t dq,
                 mpz_t qinv) {

  mpz_t m1, m2, h;

  mpz_inits(m1, m2, h, NULL);

  // m1 = c^dp mod p
  mpz_powm(m1, c, dp, p);

  // m2 = c^dq mod q
  mpz_powm(m2, c, dq, q);

  /*
     h = qinv * (m1 - m2) mod p
  */
  mpz_sub(h, m1, m2);
  mpz_mul(h, h, qinv);
  mpz_mod(h, h, p);

  /*
     m = m2 + h*q
  */
  mpz_mul(h, h, q);
  mpz_add(m, m2, h);

  mpz_clears(m1, m2, h, NULL);
}

int main(int argc, char *argv[]) {
  // Usage : ./rsa -e/-c message/cipher
  if (argc != 3) {
    printf("Usage: ./rsa -e/-d message/cipher\n");
    return EXIT_FAILURE;
  }
  if (!file_exists("./keys/public.txt") || !file_exists("./keys/private.txt")) {
    printf("Clés absentes, génération RSA...\n");
    rsa_keygen(2048);
  }
  mpz_t n, e, p, q, dp, dq, qinv;
  mpz_inits(n, e, p, q, dp, dq, qinv, NULL);
  load_public_key("./keys/public.txt", n, e);
  load_private_key("./keys/private.txt", p, q, dp, dq, qinv);

  mpz_t m, c;
  mpz_inits(m, c, NULL);
  if (strcmp(argv[1], "-e") == 0) {
    printf("Go to cipher !\n");
    mpz_set_str(m, argv[2], 16);
    gmp_printf("message  = %Zx\n", m);
    encrypt_crt(c, m, p, q, e, qinv);
    gmp_printf("cipher_fault   = %Zx\n", c);
  } else if (strcmp(argv[1], "-d") == 0) {
    printf("Go to decipher !\n");
    mpz_set_str(c, argv[2], 16);
    gmp_printf("cipher   = %Zx\n", c);
    decrypt_crt(m, c, p, q, dp, dq, qinv);
    gmp_printf("message  = %Zx\n", m);
  } else {
    printf("Only option : -e to encrypt and -d to decrypt\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}