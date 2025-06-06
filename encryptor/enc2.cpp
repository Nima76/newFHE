//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : CLIENT SIDE

#include "openfhe.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "tee_data";
const std::string PRIVATEKEY = "private_data";
const std::string RESULTSFOLDER = "data";
const std::string CRYPTOCONTEXT = "cryptocontext";

    
/////////////////////////////////////////////
//                                         //
//               |MAIN|                    //
//                                         //
/////////////////////////////////////////////


int main()
{
      //cryptocontext setting
      CCParams<CryptoContextBGVRNS> parameters;
      parameters.SetMultiplicativeDepth(1);
      parameters.SetPlaintextModulus(65537);

      CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

      cc->Enable(PKE);
      cc->Enable(KEYSWITCH);
      cc->Enable(LEVELEDSHE);
      
      //key generation
      KeyPair<DCRTPoly> keyPair;
      keyPair = cc->KeyGen();
      const PublicKey<DCRTPoly> pk = keyPair.publicKey;
      const PrivateKey<DCRTPoly> sk = keyPair.secretKey;
      
      cc->EvalMultKeyGen(sk);
      

      
      // Serialize cryptocontext
      if (!Serial::SerializeToFile(CRYPTOCONTEXT + "/cryptocontext.txt", cc, SerType::BINARY)) {
          std::cerr << "Error writing serialization of the crypto context to "
                       "cryptocontext.txt"
                    << std::endl;
          return 1;
      }
      std::cout << "The cryptocontext has been serialized." << std::endl;
      
      // Serialize the public key
      if (!Serial::SerializeToFile(RESULTSFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
          std::cerr << "Error writing serialization of private key to key-public.txt" << std::endl;
          return 1;
      }
      std::cout << "The public key has been serialized." << std::endl;
      
      // Serialize the secret key
      if (!Serial::SerializeToFile(PRIVATEKEY + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
          std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
          return 1;
      }
      std::cout << "The secret key has been serialized." << std::endl;
      
      // Serialize the relinearization (evaluation) key for homomorphic
      // multiplication
      std::ofstream emkeyfile(RESULTSFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
      if (emkeyfile.is_open()) {
          if (cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
              std::cerr << "Error writing serialization of the eval mult keys to "
                           "key-eval-mult.txt"
                        << std::endl;
              return 1;
          }
          std::cout << "The eval mult keys have been serialized." << std::endl;

          emkeyfile.close();
      }
      else {
          std::cerr << "Error serializing eval mult keys" << std::endl;
          return 1;
      }
      


        std::vector<int64_t> vectorOfInts1 = {1,1,1,1};
        Plaintext plaintext1 = cc->MakePackedPlaintext(vectorOfInts1);

        std::vector<int64_t> vectorOfInts2 = {1,1,1,1};
        Plaintext plaintext2 = cc->MakePackedPlaintext(vectorOfInts2);

        std::cout << "Decision tree succesfully built from the input file." << std::endl;

        // Nettoyage de la mémoire (supprimer les sous-arbres)
        // Ajoutez une fonction `freeTree` si nécessaire pour libérer les enfants dynamiques

      auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
      auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);
      
      if (!Serial::SerializeToFile(RESULTSFOLDER + "/enc_file1.txt", ciphertext1, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext1  to enc_file1.txt" << std::endl;
        return 1;
    }
    if (!Serial::SerializeToFile(RESULTSFOLDER + "/enc_file2.txt", ciphertext2, SerType::BINARY)) {
      std::cerr << "Error writing serialization of ciphertext2  to enc_file2.txt" << std::endl;
      return 1;
  }


      return 0;
}