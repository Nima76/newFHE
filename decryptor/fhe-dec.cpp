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
const std::string PRIVATEFOLDER = "private_data";
const std::string RESULTSFOLDER = "results";
const std::string TIMINGFOLDER = "timing";
const std::string CRYPTOCONTEXTFOLDER = "cryptocontext";

// Function to write timing results to file
void writeTimingToFile(const std::string& filename, const std::string& operation, double timeInMs) {
    std::ofstream outfile(TIMINGFOLDER + "/" + filename, std::ios::app);
    if (!outfile) {
        std::cerr << "Could not open timing file for writing" << std::endl;
        return;
    }
    outfile << operation << "," << timeInMs << std::endl;
    outfile.close();
}

int main()
{
    std::string timingFile = "timing_decryption.csv";
	//getting the crypto-context
	std::ofstream timingInit(TIMINGFOLDER + "/" + timingFile);
    timingInit << "Operation,TimeInMilliseconds" << std::endl;
    timingInit.close();
    auto startTotal = high_resolution_clock::now();
    auto startContextLoad = high_resolution_clock::now();
    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(CRYPTOCONTEXTFOLDER + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;
    auto stopContextLoad = high_resolution_clock::now();
    double contextLoadTime = duration_cast<milliseconds>(stopContextLoad - startContextLoad).count();
    writeTimingToFile(timingFile, "Context_Loading", contextLoadTime);
    
    //getting the secret key
    auto startKeyLoad = high_resolution_clock::now();
    PrivateKey<DCRTPoly> sk;
    if (Serial::DeserializeFromFile(PRIVATEFOLDER + "/key-private.txt", sk, SerType::BINARY) == false) {
        std::cerr << "Could not read secret key" << std::endl;
        return 1;
    }
    std::cout << "The secret key has been deserialized." << std::endl;
    auto stopKeyLoad = high_resolution_clock::now();
    double keyLoadTime = duration_cast<milliseconds>(stopKeyLoad - startKeyLoad).count();
    writeTimingToFile(timingFile, "SecretKey_Loading", keyLoadTime);    
    //getting the encrypted result
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
    //decrypting the result
	auto startDecryption = high_resolution_clock::now();
    Plaintext final_output;
	cc->Decrypt(sk, output_ciphertext, &final_output);
	std::cout << "OUTPUT VALUE : " << final_output << std::endl;
	auto stopDecryption = high_resolution_clock::now();
    double decryptionTime = duration_cast<milliseconds>(stopDecryption - startDecryption).count();
    writeTimingToFile(timingFile, "Decryption", decryptionTime);

	//saving the decrypted result
	auto startSaving = high_resolution_clock::now();
    std::string filepath = "results/result.txt";
	std::ofstream outfile(filepath);
    if (!outfile) {
	   std::cout << "Could not open the target file for saving the decrypted result" << std::endl;
       return 1; 
    }
    outfile << final_output << std::endl;
    outfile.close();
	
	//main return value
	auto stopSaving = high_resolution_clock::now();
    double savingTime = duration_cast<milliseconds>(stopSaving - startSaving).count();
    writeTimingToFile(timingFile, "Result_Saving", savingTime);
    
    auto stopTotal = high_resolution_clock::now();
    double totalTime = duration_cast<milliseconds>(stopTotal - startTotal).count();
    writeTimingToFile(timingFile, "Total_Decryption_Process", totalTime);
    
    // Write configuration to file for reference
    std::ofstream configFile(RESULTSFOLDER + "/config.txt");
    configFile << "Output File: " << filepath << std::endl;
    configFile.close();

    return 0;
}
