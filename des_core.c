#include "des.h"
#include "des_tables.h" 
#include <stdio.h>     

/**
 * @brief Applica una tabella di permutazione a un blocco di input.
 *
 * @param input L'input da permutare (fino a 64 bit).
 * @param table La tabella di permutazione (es. IP, P, E, ecc.).
 * @param input_size Dimensione in bit dell'input.
 * @param output_size Dimensione in bit dell'output.
 * @return Il risultato della permutazione (fino a 64 bit).
 */
uint64_t permute_bits(uint64_t input, const uint8_t table[], size_t input_size, size_t output_size) {
    
    uint64_t output = 0;

    for (size_t i = 0; i < output_size; i++) {
        
        // table[i] ci dà la posizione FIPS (1-based)
        uint8_t input_bit_pos_fips = table[i]; 

        // Conversione nella posizione FIPS in un indice bitwise
        uint8_t src_bit_index = (uint8_t)input_size - input_bit_pos_fips;

        // Estrazione del singolo bit dall'input
        uint64_t bit_value = (input >> src_bit_index) & 1ULL;

        // Calcolo la posizione di destinazione nell'output
        uint8_t dst_bit_index = (uint8_t)output_size - 1 - (uint8_t)i;

        // Scrittoura del bit nell'output
        output |= (bit_value << dst_bit_index);
    }
    
    return output;
}


/**
 * @brief La funzione F di Feistel
 * * Esegue i 4 passaggi: Espansione, XOR, Sostituzione, Permutazione.
 * @param right_half I 32 bit della metà destra (R)
 * @param subkey I 48 bit della sotto-chiave di questo round (K)
 * @return I 32 bit di output della funzione F
 */
uint32_t feistel_function_F(uint32_t right_half, uint64_t subkey) {
    
    // 1. Espansione (E-Box): 32 bit -> 48 bit
    uint64_t expanded_R = permute_bits(right_half, E_BOX, 32, 48);

    // 2. XOR con la Chiave
    uint64_t xor_result = expanded_R ^ subkey;

    // 3. Sostituzione (S-BOX): 48 bit -> 32 bit
    uint32_t sbox_output = 0;

    // Iteriamo sulle 8 S-BOX
    for (int i = 0; i < 8; i++) {
        
        // Estraiamo il blocco di 6 bit per questa S-BOX
        uint8_t six_bits = (uint8_t)((xor_result >> (42 - i * 6)) & 0x3F); // 0x3F è 00111111

        // La RIGA è composta dai 2 bit esterni (bit 5 e bit 0)
        uint8_t b1 = (six_bits >> 5) & 0x01; // Isola il bit 5 (b1)
        uint8_t b6 = (six_bits & 0x01);       // Isola il bit 0 (b6)
        uint8_t row = (b1 << 1) | b6;         // Combina: (b1, b6)
        
        // La COLONNA è composta dai 4 bit interni (bit 4-1)
        uint8_t col = (six_bits >> 1) & 0x0F; // Isola i bit 4,3,2,1

        // Eseguiamo il lookup nella S-BOX
        uint8_t s_value = S_BOX[i][row][col]; // s_value è un numero 0-15 (4 bit)
        
        // Aggiungiamo questo valore a 4 bit al nostro output
        sbox_output |= ((uint32_t)s_value << (28 - i * 4));
    }

    // 4. Permutazione (P-Box): 32 bit -> 32 bit
    uint32_t final_F_result = (uint32_t)permute_bits(sbox_output, P_BOX, 32, 32);

    return final_F_result;
}


/**
 * @brief Cifra un singolo blocco di 64 bit usando la Rete di Feistel.
 */
uint64_t des_encrypt_block(uint64_t block, const uint64_t subkeys[16]) {

    // 1. Permutazione Iniziale (IP)
    uint64_t permuted_block = permute_bits(block, IP, 64, 64);

    // 2. Divisione in L0 e R0
    uint32_t L = (uint32_t)(permuted_block >> 32); 
    uint32_t R = (uint32_t)(permuted_block & 0xFFFFFFFF);

    // 3. 16 Round di Cifratura
    for (int i = 0; i < 16; i++) {
        
        uint32_t F_result = feistel_function_F(R, subkeys[i]);
        uint32_t temp_L = L;
        L = R;
        R = temp_L ^ F_result;
    }
    
    // 4. Combinazione e Scambio Finale
    uint64_t combined = ((uint64_t)R << 32) | (uint64_t)L;

    // 5. Permutazione Finale (IP-1)
    uint64_t ciphertext = permute_bits(combined, IP_INV, 64, 64);

    return ciphertext;
}

/**
 * @brief Decifra un singolo blocco di 64 bit.
 */
uint64_t des_decrypt_block(uint64_t block, const uint64_t subkeys[16]) {
    
    // 1. Permutazione Iniziale (IP)
    uint64_t permuted_block = permute_bits(block, IP, 64, 64);

    // 2. Divisione
    uint32_t L = (uint32_t)(permuted_block >> 32);
    uint32_t R = (uint32_t)(permuted_block & 0xFFFFFFFF);

    // 3. 16 Round di Decifratura (CHIAVI IN ORDINE INVERSO)
    for (int i = 15; i >= 0; i--) { // <-- L'UNICA DIFFERENZA
        
        uint32_t F_result = feistel_function_F(R, subkeys[i]);
        uint32_t temp_L = L;
        L = R;
        R = temp_L ^ F_result;
    }

    // 4. Combinazione e Scambio Finale
    uint64_t combined = ((uint64_t)R << 32) | (uint64_t)L;

    // 5. Permutazione Finale (IP-1)
    uint64_t plaintext = permute_bits(combined, IP_INV, 64, 64);

    return plaintext;
}


/**
 * @brief Genera le 16 sotto-chiavi a 48 bit dalla master key a 64 bit.
 */
void generate_subkeys(uint64_t key, uint64_t subkeys[16]) {
    
    // 1. Applica PC-1 (64 bit -> 56 bit)
    uint64_t key_56 = permute_bits(key, PC1, 64, 56);

    // 2. Divisione in C e D (28 bit ciascuno)
    uint32_t C = (uint32_t)((key_56 >> 28) & 0x0FFFFFFF); // 0x0FFFFFFF è una maschera a 28 '1'
    uint32_t D = (uint32_t)(key_56 & 0x0FFFFFFF);

    // 3. 16 Round di generazione
    for (int i = 0; i < 16; i++) {
        
        // 3a. Prendi il numero di shift per questo round
        int shift = KEY_SHIFTS[i];

        // 3b. Esegui la rotazione a sinistra di 'shift' bit (su 28 bit)
        C = ((C << shift) & 0x0FFFFFFF) | (C >> (28 - shift));
        D = ((D << shift) & 0x0FFFFFFF) | (D >> (28 - shift));

        // 3c. Combina C e D in un blocco da 56 bit
        uint64_t combined_CD = ((uint64_t)C << 28) | D;

        // 3d. Applica PC-2 (56 bit -> 48 bit) e salva la sotto-chiave
        subkeys[i] = permute_bits(combined_CD, PC2, 56, 48);
    }
}
