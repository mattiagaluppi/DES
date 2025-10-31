#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stddef.h>

#include "des_tables.h"

// 8 B -> 64 b
#define DES_BLOCK_SIZE 8

/**
 * @brief Genera le 16 sotto-chiavi di 48 bit dal MK di 64 bit.
 * @param key La chiave principale (64 bit).
 * @param subkeys Array di output dove verranno memorizzate le 16 sotto-chiavi.
 */
void generate_subkeys(uint64_t key, uint64_t subkeys[16]);

/**
 * @brief Cifra un singolo blocco di 64 bit.
 * @param block Il blocco di testo in chiaro (64 bit).
 * @param subkeys Le 16 sotto-chiavi generate da generate_subkeys().
 * @return Il blocco cifrato (64 bit).
 */
uint64_t des_encrypt_block(uint64_t block, const uint64_t subkeys[16]);

/**
 * @brief Decifra un singolo blocco di 64 bit.
 * @param block Il blocco di testo cifrato (64 bit).
 * @param subkeys Le 16 sotto-chiavi generate da generate_subkeys().
 * @return Il blocco decifrato (64 bit).
 */
uint64_t des_decrypt_block(uint64_t block, const uint64_t subkeys[16]);


/**
 * @brief Applica una tabella di permutazione a un blocco di input.
 * @param table La tabella di permutazione (es. IP, P, E, ecc.).
 * @param input_size Dimensione in bit dell'input (es. 64 per IP).
 * @param output_size Dimensione in bit dell'output (es. 64 per IP, 48 per E).
 * @return Il risultato della permutazione.
 */
uint64_t permute_bits(uint64_t input, const uint8_t table[], size_t input_size, size_t output_size);

/**
 * @brief La funzione F di Feistel.
 */
uint32_t feistel_function_F(uint32_t right_half, uint64_t subkey);

#endif
