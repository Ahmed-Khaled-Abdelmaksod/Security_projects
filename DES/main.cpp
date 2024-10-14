#include <stdint.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

// Define this macro to enable error messages, comment it to disable error messages
#define show_err

using namespace std;

// error message

// usage message to be printed in case of invalid arguments
const string usage_msg = "\033[31mUsage1: encrypt <plaint_text.txt> <key.txt> <cipher_tex.dat>\nUsage2: decrypt <cipher_text.dat> <key.txt> <plain_text.txt>\n\033[0m";
// file not opened message
const string file_not_opened = "\033[31mError: File not opened\n\033[0m";

// key, plaintext and ciphertext global variables
uint64_t key;
uint64_t* plaintext;
streampos file_size;
uint64_t* ciphertext;
string output_file;
bool is_encrypt;

// functions definitions
/**
 * @brief Validate the arguments passed to the program.
 *
 * @param argc Number of arguments passed to the program.
 * @param argv Array of arguments passed to the program.
 * @return true if the arguments are valid, false otherwise.
 *
 * The function checks if the number of arguments is correct (5) and if the first argument is "encrypt" or "decrypt"
 * and if the files extensions are correct.
 * Correct file extensions are:
 * - encrypt: <plaint_text.txt> <key.txt> <cipher_tex.dat>
 * - decrypt: <cipher_text.dat> <key.txt> <plain_text.txt>
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
bool isLittleEndian();

int main(int argc, char* argv[]) {
    // Check if the arguments are valid
    if (!validateArgs(argc, argv)) {
        return 1;
    }

    // Open and load needed files
    if (!openFiles(argv)) {
        if (plaintext) delete[] plaintext;
        if (ciphertext) delete[] ciphertext;
        return 1;
    }

    // processing
    size_t num_blocks = file_size / 8;

    if (is_encrypt) {
        cout << "Encrypting...\n";
    } else {
        cout << "Decrypting...\n";
    }
    cout << "Key in hex: 0x" << hex << setw(16) << setfill('0') << key << endl;
    cout << "File size: " << file_size << endl;

    // encrypt or dycript each block and store it in the other array
    // for each block in the plaintext or ciphertext array
    for (size_t i = 0; i < num_blocks; i++) {
        uint64_t block = is_encrypt ? plaintext[i] : ciphertext[i];
        cout << "Block " << setw(16) << setfill('0') << i << ": " << block << endl;
        // encrypt or decrypt the block
        // store the result in the other array
        if (is_encrypt) {
            ciphertext[i] = block + key;
            cout << "Plaintext: " << setw(16) << setfill('0') << plaintext[i] << "\nCiphertext: " << setw(16) << setfill('0') << ciphertext[i] << endl;
        } else {
            plaintext[i] = block - key;
            cout << "Ciphertext: " << setw(16) << setfill('0') << ciphertext[i] << "\n Plaintext: " << setw(16) << setfill('0') << plaintext[i] << endl;
        }
    }

    // Write the output file
    if (!writeOutputFile()) {
        if (plaintext) delete[] plaintext;
        if (ciphertext) delete[] ciphertext;
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
    string input_file = argv[2];
    string key_file = argv[3];
    string output_file = argv[4];

    // Check if the first argument is "encrypt" or "decrypt"
    if (mode != "encrypt" && mode != "decrypt") {
#ifdef show_err
        cerr << usage_msg;
#endif
        return false;  // Return immediately on error
    }

    // Check file extensions based on the mode
    if ((mode == "encrypt" && (input_file.find(".txt") == string::npos || key_file.find(".txt") == string::npos || output_file.find(".dat") == string::npos)) ||
        (mode == "decrypt" && (input_file.find(".dat") == string::npos || key_file.find(".txt") == string::npos || output_file.find(".txt") == string::npos))) {
#ifdef show_err
        cerr << "\033[31mError: Invalid file extension\033[0m\n"
             << usage_msg;
#endif
        return false;  // Return immediately on error
    }

    return true;  // Return true if all checks pass
}

bool openFiles(char* argv[]) {
    // based on mode, open the files with specific types (input or output)
    string mode = argv[1];
    string input_file = argv[2];
    string key_file = argv[3];
    output_file = argv[4];

    // mode assingment
    is_encrypt = (mode == "encrypt");

    // open the input file and check if it is opened
    ifstream input_file_stream(input_file, ios::binary | ios::in | ios::ate);
    if (!input_file_stream.is_open()) {
#ifdef show_err
        cerr << file_not_opened + "Input file\n";
#endif

        input_file_stream.close();
        return false;
    }

    // open the key file and check if it is opened
    ifstream key_file_stream(key_file, ios::binary | ios::in | ios::ate);
    if (!key_file_stream.is_open()) {
#ifdef show_err
        cerr << file_not_opened + "Key file\n";
#endif

        key_file_stream.close();
        return false;
    }

    // input file processing

    file_size = input_file_stream.tellg();
    size_t num_blocks = file_size / 8;
    plaintext = new uint64_t[num_blocks];
    ciphertext = new uint64_t[num_blocks];

    input_file_stream.seekg(0, ios::beg);
    if (is_encrypt) {
        input_file_stream.read(reinterpret_cast<char*>(plaintext), file_size);
        swapEndiannessForArray(plaintext);
    } else {
        input_file_stream.read(reinterpret_cast<char*>(ciphertext), file_size);
        swapEndiannessForArray(ciphertext);
    }
    input_file_stream.close();

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
    key = swapEndianness(key);
    key_file_stream.close();

    return true;
}

bool writeOutputFile() {
    // check if output file exists
    ofstream output_file_stream = ofstream(output_file, ios::binary | ios::trunc | ios::out);
    if (!output_file_stream.is_open()) {
#ifdef show_err
        cerr << file_not_opened + "Output file\n";
#endif

        output_file_stream.close();
        return false;
    }

    if (is_encrypt) {
        swapEndiannessForArray(ciphertext);
        output_file_stream.write(reinterpret_cast<const char*>(ciphertext), file_size);
    } else {
        swapEndiannessForArray(plaintext);
        output_file_stream.write(reinterpret_cast<const char*>(plaintext), file_size);
    }
    output_file_stream.close();

    // Deallocate memory after successful operation
    if (plaintext) delete[] plaintext;
    if (ciphertext) delete[] ciphertext;

    return true;
}

inline uint64_t swapEndianness(uint64_t value) {
    // return ((value & 0x00000000000000FFULL) << 56) |
    //        ((value & 0x000000000000FF00ULL) << 40) |
    //        ((value & 0x0000000000FF0000ULL) << 24) |
    //        ((value & 0x00000000FF000000ULL) << 8) |
    //        ((value & 0x000000FF00000000ULL) >> 8) |
    //        ((value & 0x0000FF0000000000ULL) >> 24) |
    //        ((value & 0x00FF000000000000ULL) >> 40) |
    //        ((value & 0xFF00000000000000ULL) >> 56);
    if (!isLittleEndian()) return value;

    return __builtin_bswap64(value);  // GCC built-in function
}

void swapEndiannessForArray(uint64_t* arr) {
    if (!isLittleEndian()) return;

    size_t num_blocks = file_size / 8;
    for (size_t i = 0; i < num_blocks; i++) {
        arr[i] = swapEndianness(arr[i]);
    }
}

bool isLittleEndian() {
    uint16_t num = 1;
    return *(reinterpret_cast<char*>(&num)) == 1;
}