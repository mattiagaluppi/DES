#ifndef DES_TABLES_H
#define DES_TABLES_H

#include <stdint.h>

// Le tabelle sono definite come "posizioni di bit" (base 1)

// Permutazione Iniziale (IP) - 64 bit -> 64 bit
extern const uint8_t IP[64];

// Permutazione Finale (IP Inversa) - 64 bit -> 64 bit
extern const uint8_t IP_INV[64];

// ----- Componenti della Funzione F -----

// E-Box (Expansion) - 32 bit -> 48 bit
extern const uint8_t E_BOX[48];

// S-Boxes (Substitution) - 8 tabelle, 6 bit input -> 4 bit output
// Ogni S-Box è 4x16 = 64 valori
extern const uint8_t S_BOX[8][4][16];

// P-Box (Permutation) - 32 bit -> 32 bit
extern const uint8_t P_BOX[32];

// ----- Componenti del Key Schedule -----

// Permuted Choice 1 (PC-1) - 64 bit key -> 56 bit
extern const uint8_t PC1[56];

// Permuted Choice 2 (PC-2) - 56 bit (C+D) -> 48 bit subkey
extern const uint8_t PC2[48];

// Numero di shift per ogni round del Key Schedule
extern const uint8_t KEY_SHIFTS[16];

#endif // DES_TABLES_H
