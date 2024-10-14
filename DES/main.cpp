#include <stdint.h>

#include <fstream>
#include <iostream>
#include <string>

#include "SBox.cpp"

// Define this macro to enable error messages, comment it to disable error messages
#define show_err

using namespace std;

// error message

// usage message to be printed in case of invalid arguments
const char usage_msg[] = "\033[31mUsage1: encrypt <plaint_text.txt> <key.txt> <cipher_tex.dat>\nUsage2: decrypt <cipher_text.dat> <key.txt> <plain_text.txt>\n\033[0m";
// file not opened message
const char file_not_opened[] = "\033[31mError: File not opened\n\033[0m";

// key, plaintext and ciphertext global variables
uint64_t key;
uint64_t* data_blocks = nullptr;
string output_file;
bool is_encrypt;
size_t num_blocks;

// DES Tables
// left shift table, position is the (round number - 1), value is the number of bits to shift and rotate
const int left_shift_table[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// functions definitions
/**
 * @brief Validate the arguments passed to the program.
 *
 * @param argc Number of arguments passed to the program.
 * @param argv Array of arguments passed to the program.
 * @return true if the arguments are valid, false otherwise.
 *
 * The function checks if the number of arguments is correct (5) and if the first argument is "encrypt" or "decrypt".
 *
 */
bool validateArgs(int argc, char* argv[]);

/**
 * @brief Open and read the files passed as arguments to the program.
 *
 * @param argv Array of arguments passed to the program.
 * @return true if the files are opened successfully, false otherwise.
 *
 * The function opens the files passed as arguments to the program and checks if they exist.
 * It assigns the mode of the operation to the global variable mode.
 * It reads the key variable with the key value.
 * It reads the plaintext or ciphertext based on the mode of the operation.
 * It closes the files after reading the needed data.
 * It initializes the output file and assignes it to the global variable output_file_stream.
 * It initiallize the plaintext or ciphertext based on the mode of the operation to be written to as the output.
 *
 */
bool openFiles(char* argv[]);

/**
 * @brief Write the output file.
 *
 * @return true if the output file is written successfully, false otherwise.
 *
 * The function writes the output file based on the mode of the operation.
 * If the mode is "encrypt", it writes the ciphertext to the output file.
 * If the mode is "decrypt", it writes the plaintext to the output file.
 * It deletes the plaintext and ciphertext arrays after writing the output file.
 */
bool writeOutputFile();

/**
 * @brief Swap the endianness of a 64-bit integer  (little-endian to big-endian only).
 *
 * @note The function uses the GCC built-in function __builtin_bswap64 to swap the endianness of the 64-bit integer.
 * @note The function is only used for little-endian systems, otherwise, it returns the same value.
 *
 * @param value 64-bit integer to swap its endianness.
 * @return 64-bit integer with big endianness.
 */
inline uint64_t swapEndianness(uint64_t value);

/**
 * @brief Swap the endianness of a 64-bit integer array, only to be used for little-endian systems.
 *
 * @param arr 64-bit integer array to swap its endianness.
 *
 * The function swaps the endianness of each element in the array.
 * It uses the swapEndiannesss function to swap the endianness of each element to big-endian.
 * @note The function modifies the array in place.
 * @note The size of the arr is file_size / 8.
 */
void swapEndiannessForArray(uint64_t* arr);

/**
 * @brief Check if the system is little-endian.
 *
 * @return true if the system is little-endian, false otherwise.
 */
inline bool isLittleEndian();

/**
 * @brief Process the data based on the mode of the operation.
 *
 * The function performs the encryption or decryption based on the mode of the operation.
 * It uses the DES algorithm to encrypt or decrypt the data.
 */
void processData();

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
void keyGeneration(uint64_t* keys);

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
inline uint32_t leftShiftRotate(uint32_t value, int round);

/**
 * @brief Perform the DES algorithm on a 64-bit block using the generated keys.
 *
 * @param block 64-bit block to perform the DES algorithm on.
 * @param keys Array of 16 64-bit integers to use in the DES algorithm.
 * @return 64-bit block after performing the DES algorithm.
 *
 */
uint64_t DES(const uint64_t& block, const uint64_t* keys);

/**
 * @brief Perform a single round of the DES algorithm on a 32-bit right half of the block.
 *
 * @param r 32-bit right half of the block to perform the DES round on.
 * @param key 48-bit key to use in the DES round.
 * @return 32-bit right half of the block after performing the DES round (right half operaions only).
 *
 */
inline uint64_t DES_round(uint64_t r, const uint64_t& key);

int main(int argc, char* argv[]) {
    // Check if the arguments are valid
    if (!validateArgs(argc, argv)) {
        return 1;
    }

    // Open and load needed files
    if (!openFiles(argv)) {
        delete[] data_blocks;
        return 1;
    }

    // Perform the encryption or decryption
    processData();

    // Write the output file
    if (!writeOutputFile()) {
        delete[] data_blocks;
        return 1;
    }
    return 0;
}

bool validateArgs(int argc, char* argv[]) {
    // Check if the number of arguments is correct
    if (argc != 5) {
#ifdef show_err
        cerr << usage_msg;
#endif
        return false;  // Return immediately on error
    }

    // Cache the arguments as strings
    string mode = argv[1];

    // Check if the first argument is "encrypt" or "decrypt"
    if (mode != "encrypt" && mode != "decrypt") {
#ifdef show_err
        cerr << usage_msg;
#endif
        return false;  // Return immediately on error
    }

    // mode assingment
    is_encrypt = (mode == "encrypt");

    return true;  // Return true if all checks pass
}

bool openFiles(char* argv[]) {
    string input_file = argv[2];
    string key_file = argv[3];
    output_file = argv[4];

    // open the input file and check if it is opened
    ifstream input_file_stream(input_file, ios::binary | ios::ate);
    if (!input_file_stream.is_open()) {
#ifdef show_err
        cerr << file_not_opened << "Input file\n";
#endif
        return false;
    }

    // open the key file and check if it is opened
    ifstream key_file_stream(key_file, ios::binary | ios::ate);
    if (!key_file_stream.is_open()) {
#ifdef show_err
        cerr << file_not_opened << "Key file\n";
#endif
        return false;
    }

    // input file processing

    streampos file_size = input_file_stream.tellg();
    num_blocks = file_size / 8;

    data_blocks = new uint64_t[num_blocks];

    input_file_stream.seekg(0, ios::beg);
    input_file_stream.read(reinterpret_cast<char*>(data_blocks), file_size);
    input_file_stream.close();

    // Swap endianness if needed
    swapEndiannessForArray(data_blocks);

    // key file processing
    size_t key_size = key_file_stream.tellg();

    if (key_size != 8) {
#ifdef show_err
        cerr << "\033[31mError: Key file must contain exactly eight bytes.\033[0m\n";
#endif

        return false;
    }

    key_file_stream.seekg(0, ios::beg);
    key_file_stream.read(reinterpret_cast<char*>(&key), 8);
    key_file_stream.close();

    // Swap endianness if needed
    key = swapEndianness(key);

    return true;
}

bool writeOutputFile() {
    // Swap endianness back if needed
    swapEndiannessForArray(data_blocks);

    // check if output file exists
    ofstream output_file_stream = ofstream(output_file, ios::binary | ios::trunc);
    if (!output_file_stream.is_open()) {
#ifdef show_err
        cerr << file_not_opened << "Output file\n";
#endif
        return false;
    }

    // write the data to the output file
    output_file_stream.write(reinterpret_cast<char*>(data_blocks), num_blocks * 8);
    output_file_stream.close();

    delete[] data_blocks;

    return true;
}

inline uint64_t swapEndianness(uint64_t value) {
    if (!isLittleEndian()) return value;

    return ((value & 0x00000000000000FFULL) << 56) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x00000000FF000000ULL) << 8) |
           ((value & 0x000000FF00000000ULL) >> 8) |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0xFF00000000000000ULL) >> 56);
}

void swapEndiannessForArray(uint64_t* arr) {
    if (!isLittleEndian()) return;

    for (size_t i = 0; i < num_blocks; i++) {
        arr[i] = swapEndianness(arr[i]);
    }
}

bool isLittleEndian() {
    uint16_t num = 1;
    return *(reinterpret_cast<char*>(&num)) == 1;
}

void processData() {
    // keys generation
    uint64_t keys[16];  // each key is a 48 bit ater permutation choice 2

    // apply DES algorithm into each block
    for (size_t i = 0; i < num_blocks; i++) {
        data_blocks[i] = DES(data_blocks[i], keys);
    }
}

void keyGeneration(uint64_t* keys) {
    // permutation choice 1
    // key = ??
    // TODO: implement permutation choice 1

    // split the key into two halves

    /// left half
    uint32_t c = (key & 0x00FFFFFFF0000000) >> 28;  // left half
    /// right half
    uint32_t d = (key & 0x000000000FFFFFFF);  // right half

    // create the whole 16 key
    for (int i = 0; i < 16; i++) {
        // left shift and rotate
        c = leftShiftRotate(c, i);
        d = leftShiftRotate(d, i);

        // combine the two halves
        keys[i] = ((uint64_t)c << 28) | d;

        // permutation choice 2 for each key
        // keys[i] =??
        // TODO: implement permutation choice 2
    }

    // for decryption, reverse the order of the keys
    if (!is_encrypt) {
        for (int i = 0; i < 8; i++) {
            uint64_t temp = keys[i];
            keys[i] = keys[15 - i];
            keys[15 - i] = temp;
        }
    }
}

inline uint32_t leftShiftRotate(uint32_t value, int round) {
    int shifts = left_shift_table[round];
    return ((value << shifts) | (value >> (28 - shifts))) & 0x0FFFFFFF;
}

uint64_t DES(const uint64_t& block, const uint64_t* keys) {
    // initial permutation
    // block_new = ??
    // TODO: implement initial permutation

    uint64_t block_new = 0;  // TODO change this line

    uint32_t l = static_cast<uint32_t>(block_new >> 32);
    uint32_t r = static_cast<uint32_t>(block_new & 0xFFFFFFFF);

    // perform 16 rounds
    for (int i = 0; i < 16; i++) {
        uint32_t temp = r;
        r = l ^ DES_round(r, keys[i]);
        l = temp;
    }

    // comnine the two halves and swap them
    block_new = ((uint64_t)r << 32) | l;

    // final permutation
    // TODO: implement final permutation

    return block_new;
}

uint64_t DES_round(uint64_t r, const uint64_t& key) {
    // right half operations

    // expansion permutation
    // TODO: implement expansion permutation
    // r = ??

    // XOR with key, both 48 bits
    r = (r ^ key);

    // S-boxes, result is 32 bits
    r = SBox(r);

    // permutation
    // TODO: implement permutation
    // r = ??

    // combine the two halves
    return r;
}