//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : RESULT DECRYPTION

#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

#include <chrono>
#include <iostream>
#include <fstream>
#include <string>

using namespace lbcrypto;
using namespace std::chrono;

const std::string DATAFOLDER = "data";
const std::string PrivateKeyFolder = "private_data";
const std::string RESULTSFOLDER = "results";

// Function to write timing results to file
void writeTimingToFile(const std::string& filename, const std::string& operation, double timeInMs) {
    std::ofstream outfile(RESULTSFOLDER + "/" + filename, std::ios::app);
    if (!outfile) {
        std::cerr << "Could not open timing file for writing" << std::endl;
        return;
    }
    outfile << operation << "," << timeInMs << std::endl;
    outfile.close();
}

int main(int argc, char* argv[])
{
    // Default parameters
    std::string outputFile = "result.txt";
    std::string timingFile = "timing_decryption.csv";
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "--timing" && i + 1 < argc) {
            timingFile = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n"
                      << "Options:\n"
                      << "  --output FILE  Specify output file for decrypted result (default: result.txt)\n"
                      << "  --timing FILE  Specify timing output file (default: timing_decryption.csv)\n"
                      << "  --help         Display this help message\n";
            return 0;
        }
    }
    
    // Create results directory if it doesn't exist
    //system(("mkdir -p " + RESULTSFOLDER).c_str());
    
    // Initialize timing file with header
    std::ofstream timingInit(RESULTSFOLDER + "/" + timingFile);
    timingInit << "Operation,TimeInMilliseconds" << std::endl;
    timingInit.close();
    
    auto startTotal = high_resolution_clock::now();
    
    // Getting the crypto-context
    auto startContextLoad = high_resolution_clock::now();
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;
    auto stopContextLoad = high_resolution_clock::now();
    double contextLoadTime = duration_cast<milliseconds>(stopContextLoad - startContextLoad).count();
    writeTimingToFile(timingFile, "Context_Loading", contextLoadTime);
    
    // Getting the secret key
    auto startKeyLoad = high_resolution_clock::now();
    PrivateKey<DCRTPoly> sk;
    if (Serial::DeserializeFromFile(PrivateKeyFolder + "/key-private.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;
    auto stopKeyLoad = high_resolution_clock::now();
    double keyLoadTime = duration_cast<milliseconds>(stopKeyLoad - startKeyLoad).count();
    writeTimingToFile(timingFile, "SecretKey_Loading", keyLoadTime);
    
    // Getting the encrypted result
    auto startCiphertextLoad = high_resolution_clock::now();
    Ciphertext<DCRTPoly> output_ciphertext;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/output_ciphertext.txt", output_ciphertext, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
    }
    std::cout << "The encrypted result of the homomorphic evaluation has been deserialized." << std::endl;
    auto stopCiphertextLoad = high_resolution_clock::now();
    double ciphertextLoadTime = duration_cast<milliseconds>(stopCiphertextLoad - startCiphertextLoad).count();
    writeTimingToFile(timingFile, "Ciphertext_Loading", ciphertextLoadTime);
    
    // Decrypting the result
    auto startDecryption = high_resolution_clock::now();
    Plaintext final_output;
    cc->Decrypt(sk, output_ciphertext, &final_output);
    std::cout << "OUTPUT VALUE : " << final_output << std::endl;
    auto stopDecryption = high_resolution_clock::now();
    double decryptionTime = duration_cast<milliseconds>(stopDecryption - startDecryption).count();
    writeTimingToFile(timingFile, "Decryption", decryptionTime);
    
    // Saving the decrypted result
    auto startSaving = high_resolution_clock::now();
    std::string filepath = RESULTSFOLDER + "/" + outputFile;
    std::ofstream outfile(filepath);
    if (!outfile) {
       std::cout << "Could not open the target file for saving the decrypted result" << std::endl;
       return 1; 
    }
    outfile << final_output << std::endl;
    outfile.close();
    auto stopSaving = high_resolution_clock::now();
    double savingTime = duration_cast<milliseconds>(stopSaving - startSaving).count();
    writeTimingToFile(timingFile, "Result_Saving", savingTime);
    
    auto stopTotal = high_resolution_clock::now();
    double totalTime = duration_cast<milliseconds>(stopTotal - startTotal).count();
    writeTimingToFile(timingFile, "Total_Decryption_Process", totalTime);
    
    // Write configuration to file for reference
    std::ofstream configFile(RESULTSFOLDER + "/config.txt");
    configFile << "Output File: " << outputFile << std::endl;
    configFile.close();
    
    return 0;
}