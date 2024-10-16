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

//permutaion choice 1 table
const int pc_1[56] = {  57 ,49 ,41 ,33 ,25 ,17 ,9  ,
                        1  ,58 ,50 ,42 ,34 ,26 ,18 ,
                        10 ,2  ,59 ,51 ,43 ,35 ,27 ,
                        19 ,11 ,3  ,60 ,52 ,44 ,36 ,
                        63 ,55 ,47 ,39 ,31 ,23 ,15 ,
                        7  ,62 ,54 ,46 ,38 ,30 ,22 ,
                        14 ,6  ,61 ,53 ,45 ,37 ,29 ,
                        21 ,13 ,5  ,28 ,20 ,12 ,4 };


//permutation choice 2 table
const int pc_2[48] = {  14 ,17 ,11 ,24 ,1  ,5  ,
                        3  ,28 ,15 ,6  ,21 ,10 ,
                        23 ,19 ,12 ,4  ,26 ,8  ,
                        16 ,7  ,27 ,20 ,13 ,2  ,
                        41 ,52 ,31 ,37 ,47 ,55 ,
                        30 ,40 ,51 ,45 ,33 ,48 ,
                        44 ,49 ,39 ,56 ,34 ,53 ,
                        46 ,42 ,50 ,36 ,29 ,32 };              


// intital permutation table
const int IP_t[64] = { 	58 ,50 ,42 ,34 ,26 ,18 ,10 ,2 ,  
                        60 ,52 ,44 ,36 ,28 ,20 ,12 ,4 ,
                        62 ,54 ,46 ,38 ,30 ,22 ,14 ,6 ,
                        64 ,56 ,48 ,40 ,32 ,24 ,16 ,8 ,
                        57 ,49 ,41 ,33 ,25 ,17 ,9  ,1 ,
                        59 ,51 ,43 ,35 ,27 ,19 ,11 ,3 ,
                        61 ,53 ,45 ,37 ,29 ,21 ,13 ,5 ,
                        63 ,55 ,47 ,39 ,31 ,23 ,15 ,7 };    


//final permutation table
const int P_1[64] = { 	40 ,8  ,48 ,16 ,56 ,24 ,64 ,32 ,
                        39 ,7  ,47 ,15 ,55 ,23 ,63 ,31 ,
                        38 ,6  ,46 ,14 ,54 ,22 ,62 ,30 ,
                        37 ,5  ,45 ,13 ,53 ,21 ,61 ,29 ,
                        36 ,4  ,44 ,12 ,52 ,20 ,60 ,28 ,
                        35 ,3  ,43 ,11 ,51 ,19 ,59 ,27 ,
                        34 ,2  ,42 ,10 ,50 ,18 ,58 ,26 ,
                        33 ,1  ,41 ,9  ,49 ,17 ,57 ,25 };
              


 // expantion table
const int E_t[48] = { 	32 ,1  ,2  ,3  ,4  ,5  ,
                        4  ,5  ,6  ,7  ,8  ,9  ,
                        8  ,9  ,10 ,11 ,12 ,13 ,
                        12 ,13 ,14 ,15 ,16 ,17 ,
                        16 ,17 ,18 ,19 ,20 ,21 ,
                        20 ,21 ,22 ,23 ,24 ,25 ,
                        24 ,25 ,26 ,27 ,28 ,29 ,
                        28 ,29 ,30 ,31 ,32 ,1 };


// permutation table
const int P[32] = { 	16 ,7  ,20 ,21 ,
                        29 ,12 ,28 ,17 ,
                        1  ,15 ,23 ,26 ,
                        5  ,18 ,31 ,10 ,
                        2  ,8  ,24 ,14 ,
                        32 ,27 ,3  ,9  ,
                        19 ,13 ,30 ,6  ,
                        22 ,11 ,4  ,25 };





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
 * @brief converts the input key string to into binary representation
 * 
 * @param inputKey 
 * @param key 
 */
void convertHexKeyIntoBinary(unsigned char *inputKey, uint64_t key);


/**
 * @brief General permutation function for DES.
 *
 * @param input The input data to permute.
 * @param table The permutation table defining the new bit order.
 * @param table_size The number of bits to permute.
 * @param total_bits The total number of bits in the input.
 * @return The permuted output data.
 */
uint64_t permute(uint64_t input, const int* table, int table_size, int total_bits) {
    uint64_t output = 0;
    for(int i = 0; i < table_size; i++) {
        output <<= 1;
        // Extract the bit from the input based on the table
        output |= (input >> (total_bits - table[i])) & 0x01;
    }
    return output;
}





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
    uint64_t keys[16];  // place holder variable for 16 subkeys
    keyGeneration(keys); // each key is a 48 bit ater permutation choice 2

    // apply DES algorithm into each block
    for (size_t i = 0; i < num_blocks; i++) {
        data_blocks[i] = DES(data_blocks[i], keys);
    }
}




void keyGeneration(uint64_t* keys) {
    // Apply Permuted Choice 1 to the original key
    uint64_t permuted_key = permute(key, pc_1, 56, 64);

    // Split the permuted key into two 28-bit halves
    uint32_t C = (permuted_key >> 28) & 0x0FFFFFFF; // Left half
    uint32_t D = permuted_key & 0x0FFFFFFF;         // Right half

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
    if (!is_encrypt) {
        for (int i = 0; i < 8; i++) {
            std::swap(keys[i], keys[15 - i]);
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
   uint64_t block_new = permute(block, IP_t, 64, 64);

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
    uint64_t fp_output = permute(block_new, P_1, 64, 64);


    return fp_output;
}

uint64_t DES_round(uint64_t r, const uint64_t& key) {
    // right half operations

    // expansion permutation
    // TODO: implement expansion permutation
    // r = ??
   uint64_t expanded_r = permute(static_cast<uint64_t>(r) << 32, E_t, 48, 32);


    // XOR with key, both 48 bits
    uint64_t xor_r = (expanded_r ^ key);

    // S-boxes, result is 32 bits
    uint64_t sBox_output = SBox(xor_r);

    // permutation
    // TODO: implement permutation
    // r = ??
    uint32_t permuted_output = static_cast<uint32_t>(permute(sBox_output, P, 32, 32));

    // combine the two halves
    return permuted_output;
}