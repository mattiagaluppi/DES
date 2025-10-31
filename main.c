#include <stdio.h>
#include <stdint.h>
#include "des.h"

// Funzione helper per stampare 64 bit in esadecimale
void print_hex(const char* label, uint64_t value) {
    printf("%s: 0x%016llX\n", label, value);
}

int main() {
    printf("===== Test Implementazione DES =====\n");

    // 1. Definiamo il nostro Vettore di Test
    const uint64_t test_key       = 0x133457799BBCDFF1;
    const uint64_t test_plaintext = 0x0123456789ABCDEF;
    const uint64_t expected_ciphertext = 0x85E813540F0AB405;

    print_hex("Chiave     ", test_key);
    print_hex("Plaintext  ", test_plaintext);
    print_hex("Cipher Atteso", expected_ciphertext);
    printf("--------------------------------------\n");

    // 2. Generiamo le sotto-chiavi
    uint64_t subkeys[16];
    generate_subkeys(test_key, subkeys);
    printf("1. Sotto-chiavi generate.\n");

    // 3. Cifriamo il blocco
    uint64_t actual_ciphertext = des_encrypt_block(test_plaintext, subkeys);
    printf("2. Blocco cifrato.\n");
    print_hex("Cipher Ottenuto", actual_ciphertext);

    // 4. Verifichiamo la cifratura
    if (actual_ciphertext == expected_ciphertext) {
        printf(">>> SUCCESSO: La cifratura è corretta!\n");
    } else {
        printf(">>> FALLIMENTO: La cifratura NON è corretta.\n");
        return 1;
    }

    printf("--------------------------------------\n");

    // 5. Decifriamo il blocco
    uint64_t decrypted_plaintext = des_decrypt_block(actual_ciphertext, subkeys);
    printf("3. Blocco decifrato.\n");
    print_hex("Plaintext Ottenuto", decrypted_plaintext);

    // 6. Verifichiamo la decifratura
    if (decrypted_plaintext == test_plaintext) {
        printf(">>> SUCCESSO: La decifratura è corretta! (Roundtrip riuscito)\n");
    } else {
        printf(">>> FALLIMENTO: La decifratura NON è corretta.\n");
        return 1;
    }

    printf("======================================\n");

    return 0;
}
