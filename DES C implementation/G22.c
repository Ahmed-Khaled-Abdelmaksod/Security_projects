#include <inttypes.h>  // Include for PRIx64 macro
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// Macro to extract 6-bit chunks from the 48-bit input
#define divide_input(__INPUT__, __POS__) (uint8_t)((__INPUT__ >> ((8 - __POS__) * 6)) & 0x3F)

// global variables
uint64_t key;
uint64_t *data_blocks;
size_t num_blocks;
bool is_encrypt_mode = true;
char *output_file_name;

//------------------------------ Tables ------------------------------
// Left Shift Table
const int left_shift_table[16] = {1, 1, 2, 2,
                                  2, 2, 2, 2,
                                  1, 2, 2, 2,
                                  2, 2, 2, 1};

// Choice 1 Permutation Table
const int pc_1[56] = {57, 49, 41, 33, 25, 17, 9,
                      1, 58, 50, 42, 34, 26, 18,
                      10, 2, 59, 51, 43, 35, 27,
                      19, 11, 3, 60, 52, 44, 36,
                      63, 55, 47, 39, 31, 23, 15,
                      7, 62, 54, 46, 38, 30, 22,
                      14, 6, 61, 53, 45, 37, 29,
                      21, 13, 5, 28, 20, 12, 4};

// Choice 2 Permutation Table
const int pc_2[48] = {14, 17, 11, 24, 1, 5,
                      3, 28, 15, 6, 21, 10,
                      23, 19, 12, 4, 26, 8,
                      16, 7, 27, 20, 13, 2,
                      41, 52, 31, 37, 47, 55,
                      30, 40, 51, 45, 33, 48,
                      44, 49, 39, 56, 34, 53,
                      46, 42, 50, 36, 29, 32};

// Initial Permutation Table
const int IP_t[64] = {58, 50, 42, 34, 26, 18, 10, 2,
                      60, 52, 44, 36, 28, 20, 12, 4,
                      62, 54, 46, 38, 30, 22, 14, 6,
                      64, 56, 48, 40, 32, 24, 16, 8,
                      57, 49, 41, 33, 25, 17, 9, 1,
                      59, 51, 43, 35, 27, 19, 11, 3,
                      61, 53, 45, 37, 29, 21, 13, 5,
                      63, 55, 47, 39, 31, 23, 15, 7};

// Final Permutation Table
const int P_1[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                     39, 7, 47, 15, 55, 23, 63, 31,
                     38, 6, 46, 14, 54, 22, 62, 30,
                     37, 5, 45, 13, 53, 21, 61, 29,
                     36, 4, 44, 12, 52, 20, 60, 28,
                     35, 3, 43, 11, 51, 19, 59, 27,
                     34, 2, 42, 10, 50, 18, 58, 26,
                     33, 1, 41, 9, 49, 17, 57, 25};

// Expansion Permutation Table
const int E_t[48] = {32, 1, 2, 3, 4, 5,
                     4, 5, 6, 7, 8, 9,
                     8, 9, 10, 11, 12, 13,
                     12, 13, 14, 15, 16, 17,
                     16, 17, 18, 19, 20, 21,
                     20, 21, 22, 23, 24, 25,
                     24, 25, 26, 27, 28, 29,
                     28, 29, 30, 31, 32, 1};

// Permutation Function Table
const int P[32] = {16, 7, 20, 21,
                   29, 12, 28, 17,
                   1, 15, 23, 26,
                   5, 18, 31, 10,
                   2, 8, 24, 14,
                   32, 27, 3, 9,
                   19, 13, 30, 6,
                   22, 11, 4, 25};

// S-box Table
int S1[4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};

int S2[4][16] = {
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};

int S3[4][16] = {
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};

int S4[4][16] = {
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};

int S5[4][16] = {
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};

int S6[4][16] = {
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};

int S7[4][16] = {
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};

int S8[4][16] = {
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

//------------------------------ Functions ------------------------------
/**
 * @brief Load the content of a file into memory for data blocks global variable.
 *
 * @param file_name The name of the file to load.
 *
 */
void load_file(const char *file_name);

/**
 * @brief Save the data blocks to a file.
 *
 * @return 1 if the data was saved successfully, 0 otherwise.
 *
 * @note The output file name is stored in the global variable output_file_name.
 * @note The data to be saved is stored in the global variable data_blocks.
 * @note The number of data blocks is stored in the global variable num_blocks.
 *
 */
bool save_file();

/**
 * @brief Validate the command line arguments.
 *
 * @param argc The number of arguments.
 * @param argv The arguments.
 * @return true if the arguments are valid, false otherwise.
 */
bool validateArgsAndReadFile(int argc, char **argv);

//------------------------------ Permutation function ------------------------------
/**
 * @brief Perform a permutation on the input.
 *
 * @param input The input to permute.
 * @param table The permutation table defining the new bit order.
 * @param table_size The size of the permutation table.
 * @param total_bits The total number of bits in the input.
 * @return The permuted input.
 */
uint64_t permute(uint64_t input, const int *table, int table_size, int total_bits);

//------------------------------ S-Box functions ------------------------------
/**
 * @brief Perform an S-Box substitution on the input data.
 *
 * @param input_data
 * @param sbox The S-Box to use.
 * @return The output data.
 */
static inline uint8_t SBox_n(uint8_t input_data, int sbox[4][16]);

/**
 * @brief Perform an S-Box substitution on the input data.
 *
 * @param input_data
 * @return The output data.
 */
uint32_t SBox(uint64_t input_data);

//------------------------------ DES Functions ------------------------------
/**
 * @brief Generate all the 16 rounds 56-bit keys based on the key value (global 64 bit variable).
 *
 * @param keys Array of 16 64-bit integers to store the generated keys.
 *
 * The function generates the keys based on the key value.
 * @note The function modifies the keys array in place.
 * @note The size of the keys array is 16.
 * @note The function modifies the order of keys in Decryption mode.
 */
void keyGeneration(uint64_t *keys);

/**
 * @brief Perform the left shift and rotate operation on a 28-bit key at a specific round based on the left shift table in DES algorithm.
 *
 * @param value 32-bit integer to perform the left shift and rotate operation on.
 * @param round The round number to determine the number of bits to shift and rotate.
 * @return 32-bit integer after performing the left shift and rotate operation.
 *
 * The function performs the left shift and rotate operation on a 32-bit integer.
 * The number of bits to shift and rotate is determined by the round number.
 */
static inline uint32_t leftShiftRotate(uint32_t value, int round);

/**
 * @brief Perform the DES algorithm on a 64-bit block using the generated keys.
 *
 * @param block 64-bit block to perform the DES algorithm on.
 * @param keys Array of 16 64-bit integers to use in the DES algorithm.
 * @return 64-bit block after performing the DES algorithm.
 *
 */
uint64_t DES(uint64_t block, const uint64_t *keys);

/**
 * @brief Perform a single round of the DES algorithm on a 32-bit right half of the block.
 *
 * @param r 32-bit right half of the block to perform the DES round on.
 * @param key 48-bit key to use in the DES round.
 * @return 32-bit right half of the block after performing the DES round (right half operaions only).
 *
 */
static inline uint32_t DES_round(uint32_t r, uint64_t key);

/**
 * @brief Process the data based on the mode of the operation.
 *
 * The function performs the encryption or decryption based on the mode of the operation.
 * It uses the DES algorithm to encrypt or decrypt the data.
 */
void processData();

//------------------------------ Main ------------------------------

int main(int argc, char **argv) {
    // Validate the command line arguments and read the file
    validateArgsAndReadFile(argc, argv);

    // Perform the encryption or decryption
    // Process the data
    processData();

    // Save the data to the output file
    save_file();

    // Free the memory
    free(data_blocks);
    return 0;
}

void load_file(const char *file_name) {
    struct stat file_info;

    // Get file information
    stat(file_name, &file_info);

    // Open file in binary read mode
    FILE *file_src = fopen(file_name, "rb");

    // Calculate the number of blocks
    num_blocks = file_info.st_size / sizeof(uint64_t);

    // Allocate memory for file content as uint64_t blocks
    data_blocks = (uint64_t *)malloc(num_blocks * sizeof(uint64_t));

    // Read file content into memory
    size_t item_read = fread(data_blocks, sizeof(uint64_t), num_blocks, file_src);
    fclose(file_src);

    // Handle endianness if necessary
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    for (size_t i = 0; i < num_blocks; i++) {
        data_blocks[i] = __builtin_bswap64(data_blocks[i]);
    }
#endif
}

bool save_file() {
    // Open file in binary write mode
    FILE *file_dst = fopen(output_file_name, "wb");

    // Handle endianness if necessary
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    // Create a temporary buffer to hold swapped data
    uint64_t *temp_blocks = (uint64_t *)malloc(num_blocks * sizeof(uint64_t));

    for (size_t i = 0; i < num_blocks; i++) {
        temp_blocks[i] = __builtin_bswap64(data_blocks[i]);
    }

    // Write data to the file
    size_t items_written = fwrite(temp_blocks, sizeof(uint64_t), num_blocks, file_dst);
    free(temp_blocks);
#else
    // Write data to the file directly
    size_t items_written = fwrite(data_blocks, sizeof(uint64_t), num_blocks, file_dst);
#endif

    fclose(file_dst);
    return true;  // Success
}

bool validateArgsAndReadFile(int argc, char **argv) {
    // cache args as strings
    char *mode = argv[1];
    char *key_file = argv[2];
    char *input_file = argv[3];
    char *output_file = argv[4];

    is_encrypt_mode = (mode[0] == 'e');

    // read the key file
    FILE *key_file_ptr = fopen(key_file, "rb");
    size_t item_read = fread(&key, sizeof(uint64_t), 1, key_file_ptr);
    fclose(key_file_ptr);

    // Handle endianness for the key
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    key = __builtin_bswap64(key);
#endif

    // read the input file
    load_file(input_file);

    // set the output file name global variable
    output_file_name = output_file;

    return true;
}

uint64_t permute(uint64_t input, const int *table, int table_size, int total_bits) {
    uint64_t output = 0;
    for (int i = 0; i < table_size; i++) {
        output <<= 1;
        output |= (input >> (total_bits - table[i])) & 0x01;
    }
    return output;
}

static inline uint8_t SBox_n(uint8_t input_data, int sbox[4][16]) {
    // Extract the row from the first and last bits
    uint8_t row = ((input_data & 0x20) >> 4) | (input_data & 0x01);

    // Extract the column from the middle 4 bits
    uint8_t col = (input_data >> 1) & 0x0F;

    return sbox[row][col];
}

uint32_t SBox(uint64_t input_data) {
    // Extract 6-bit chunks for each S-box from the 48-bit input
    uint8_t s1 = SBox_n(divide_input(input_data, 1), S1);
    uint8_t s2 = SBox_n(divide_input(input_data, 2), S2);
    uint8_t s3 = SBox_n(divide_input(input_data, 3), S3);
    uint8_t s4 = SBox_n(divide_input(input_data, 4), S4);
    uint8_t s5 = SBox_n(divide_input(input_data, 5), S5);
    uint8_t s6 = SBox_n(divide_input(input_data, 6), S6);
    uint8_t s7 = SBox_n(divide_input(input_data, 7), S7);
    uint8_t s8 = SBox_n(divide_input(input_data, 8), S8);

    // Combine the 4-bit outputs from each S-box into a 32-bit value
    uint32_t output_data = (s1 << 28) | (s2 << 24) | (s3 << 20) | (s4 << 16) | (s5 << 12) | (s6 << 8) | (s7 << 4) | s8;

    return output_data;
}

void keyGeneration(uint64_t *keys) {
    // Apply Permuted Choice 1 to the original key
    uint64_t permuted_key = permute(key, pc_1, 56, 64);

    // Split the permuted key into two 28-bit halves
    uint32_t C = (uint32_t)(permuted_key >> 28) & 0x0FFFFFFF;  // Left half
    uint32_t D = (uint32_t)permuted_key & 0x0FFFFFFF;          // Right half

    // Generate 16 subkeys
    for (int i = 0; i < 16; i++) {
        // Perform left shifts according to the shift table
        C = leftShiftRotate(C, i);
        D = leftShiftRotate(D, i);

        // Combine C and D into a 56-bit key
        uint64_t combined_halves = ((uint64_t)C << 28) | D;

        // Apply Permuted Choice 2 to get the 48-bit subkey
        keys[i] = permute(combined_halves, pc_2, 48, 56);
    }

    // Reverse the order of the keys for decryption
    if (!is_encrypt_mode) {
        for (int i = 0; i < 8; i++) {
            uint64_t temp = keys[i];
            keys[i] = keys[15 - i];
            keys[15 - i] = temp;
        }
    }
}

static inline uint32_t leftShiftRotate(uint32_t value, int round) {
    int shifts = left_shift_table[round];
    return ((value << shifts) | (value >> (28 - shifts))) & 0x0FFFFFFF;
}

uint64_t DES(uint64_t block, const uint64_t *keys) {
    // initial permutation
    uint64_t block_new = permute(block, IP_t, 64, 64);

    uint32_t l = (uint32_t)(block_new >> 32);
    uint32_t r = (uint32_t)(block_new & 0xFFFFFFFF);

    // perform 16 rounds
    for (int i = 0; i < 16; i++) {
        uint32_t temp = r;
        r = l ^ DES_round(r, keys[i]);
        l = temp;
    }

    // comnine the two halves and swap them
    block_new = ((uint64_t)r << 32) | l;

    // final permutation
    uint64_t fp_output = permute(block_new, P_1, 64, 64);

    return fp_output;
}

static inline uint32_t DES_round(uint32_t r, uint64_t key) {
    // right half operations

    // expansion permutation
    uint64_t expanded_r = permute((uint64_t)r, E_t, 48, 32);

    // XOR with key, both 48 bits
    uint64_t xor_r = expanded_r ^ key;

    // S-boxes, result is 32 bits
    uint64_t sBox_output = SBox(xor_r);

    // permutation
    uint32_t permuted_output = (uint32_t)permute(sBox_output, P, 32, 32);

    return permuted_output;
}

void processData() {
    // keys generation
    uint64_t keys[16];    // place holder variable for 16 subkeys
    keyGeneration(keys);  // each key is a 48 bit ater permutation choice 2

    // apply DES algorithm into each block
    for (size_t i = 0; i < num_blocks; i++) {
        data_blocks[i] = DES(data_blocks[i], keys);
    }
}