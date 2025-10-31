# ⚙️ DES Implementation in C

A from-scratch implementation of the **Data Encryption Standard (DES)** algorithm in plain C. This project was built for educational purposes to understand the internal workings of a classic block cipher, including its Feistel network, S-Boxes, and key schedule.

> **Warning:** This implementation is for educational use only. **DES is insecure** due to its small 56-bit key size and should **never** be used for modern, secure applications. Use algorithms like AES instead.



---

## 🚀 Features

This project implements the complete DES algorithm as specified in **FIPS 46-3**:

* **Full Encryption & Decryption:** Implements the core 64-bit block cipher.
* **Feistel Network:** A 16-round Feistel structure.
* **Feistel Function (F-function):**
    * **E-Box** (Expansion)
    * **S-Boxes** (Substitution - the non-linear core)
    * **P-Box** (Permutation)
* **Key Schedule:** Generates all 16 48-bit subkeys from a 64-bit master key using **PC-1**, **PC-2**, and the specified rotational shifts.
* **Permutations:** Includes the **Initial Permutation (IP)** and **Final Permutation (IP⁻¹)**.
* **Validated:** Passes a full suite of standard DES test vectors (including weak and semi-weak keys) to ensure correctness.

---

## 📂 File Structure

The project is organized into modular files for clarity:

* `des.h`: The main header file with function prototypes and type definitions.
* `des_tables.h`: Header file declaring all the standard DES permutation and substitution tables.
* `des_tables.c`: Implementation file containing the static data for all tables (IP, S-Boxes, PC-1, etc.).
* `des_core.c`: The core logic for encryption, decryption, the F-function, and the key schedule.
* `main.c`: A test driver that runs the implementation against a set of known test vectors to verify correctness.

---

## 🛠️ How to Build and Run

This project is written in standard C and can be compiled with `gcc` or `clang`.

### 1. Compilation

Navigate to the project directory and run the following command to compile all source files into a single executable named `des_test`:

```bash
gcc main.c des_core.c des_tables.c -o des_test -W -Wall
```

### 2. Running Tests

The compiled `main.c` acts as a test bench. It will run several standard test vectors against the cipher and report on success or failure.

To run the tests, simply execute the compiled file:

```bash
./des_test
```

### 3. Expected Output

If the implementation is correct, you will see a success message for all test vectors:

```
===== Test Implementazione DES =====
Chiave     : 0x133457799BBCDFF1
Plaintext  : 0x0123456789ABCDEF
Cipher Atteso: 0x85E813540F0AB405
--------------------------------------
1. Sotto-chiavi generate.
2. Blocco cifrato.
Cipher Ottenuto: 0x85E813540F0AB405
>>> SUCCESSO: La cifratura è corretta!
--------------------------------------
3. Blocco decifrato.
Plaintext Ottenuto: 0x0123456789ABCDEF
>>> SUCCESSO: La decifratura è corretta! (Roundtrip riuscito)
======================================
```
