// test_permute.cpp

#include <stdint.h>
#include <cassert>
#include <iostream>
#include <string>

// DES Permutation Tables

// Permuted Choice 1 (PC-1) Table (56 bits)
const int pc_1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4 
};

// Permuted Choice 2 (PC-2) Table (48 bits)
const int pc_2[48] = {  
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32 
};              

// Initial Permutation (IP) Table (64 bits)
const int IP_t[64] = { 	
    58, 50, 42, 34, 26, 18, 10, 2,  
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7 
};    

// Final Permutation (FP) Table (64 bits)
const int P_1[64] = { 	
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25 
};
              
// Expansion (E) Table (32 bits to 48 bits)
const int E_t[48] = { 	
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1 
};

// Permutation (P) Table (32 bits)
const int P[32] = { 	
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25 
};

// Permute Function
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

// Helper Function to Test Permutations
/**
 * @brief Tests a given permutation table by verifying each bit's correct mapping.
 *
 * @param name The name of the permutation being tested.
 * @param table The permutation table.
 * @param table_size The number of bits in the permutation table.
 * @param total_bits The total number of bits in the input to permute.
 */
void test_permutation(const std::string& name, const int* table, int table_size, int total_bits) {
    std::cout << "Testing Permutation: " << name << std::endl;
    for(int i = 0; i < table_size; i++) {
        // Set only the bit corresponding to table[i] in input
        uint64_t input = 1ULL << (total_bits - table[i]);
        // Perform permutation
        uint64_t output = permute(input, table, table_size, total_bits);
        // The expected output should have only the (table_size - 1 - i) bit set
        uint64_t expected_output = 1ULL << (table_size - 1 - i);
        // Assert that output matches expected_output
        assert(output == expected_output);
    }
    std::cout << "Passed: " << name << std::endl << std::endl;
}

int main() {
    // Test Permuted Choice 1 (PC-1) Table
    test_permutation("Permuted Choice 1 (PC-1)", pc_1, 56, 64);
    
    // Test Permuted Choice 2 (PC-2) Table
    test_permutation("Permuted Choice 2 (PC-2)", pc_2, 48, 56);
    
    // Test Initial Permutation (IP) Table
    test_permutation("Initial Permutation (IP)", IP_t, 64, 64);
    
    // Test Final Permutation (FP) Table
    test_permutation("Final Permutation (FP)", P_1, 64, 64);
    
    // Test Expansion (E) Table
    test_permutation("Expansion Permutation (E)", E_t, 48, 32);
    
    // Test Permutation (P) Table
    test_permutation("Permutation (P)", P, 32, 32);
    
    std::cout << "\033[32mAll permutation tests passed successfully!\033[0m" << std::endl;
    return 0;
}
