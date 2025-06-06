//HOMOMORPHIC EVALUATION OF BINARY DECISION TREE FROM OPENFHE : SERVER SIDE

#include "openfhe.h"

#include <iostream>
#include <filesystem>
#include <string>
#include <cmath>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

const std::string DATAFOLDER = "data";
const std::string RESULTSFOLDER = "results";
const std::string CRYPTOCONTEXT = "cryptocontext";

//binary decision trees
typedef struct bdt
{
	std::vector<int64_t> root;
	bdt* left = nullptr;
	bdt* right = nullptr;
} bdt;

//binary decision trees encoded as plaintexts
typedef struct bdt_pt
{
	Plaintext root;
	bdt_pt* left;
	bdt_pt* right;
} bdt_pt;

//encrypted binary decision trees
typedef struct bdt_ct
{
	Ciphertext<DCRTPoly> root;
	bdt_ct* left;
	bdt_ct* right;
} bdt_ct;

//caculating the depth of the input tree
int calculateDepth(const std::string& directory) {
    int depth = 0;

    while (true) {
        // index of the last file to check for this depth
        int fileIndex = (1 << depth) - 1; // 2^depth - 1
        
        // corresponding filename
        std::string fileName = "encrypted_tree" + std::to_string(fileIndex) + ".txt";
        std::string filePath = directory + "/" + fileName;

        // checking if this file exists
        if (!fs::exists(filePath)) {
            break; // when a file is missing, the depth is calculated
        }

        ++depth; // next level
    }

    return depth;
}

//encoding a binary decision tree
bdt_pt bdt_encode(CryptoContext<DCRTPoly> cc, bdt tree)
{
	bdt_pt result;
	result.root = cc->MakePackedPlaintext(tree.root);
	result.left = new bdt_pt();
	result.right = new bdt_pt();
	if(tree.left!=NULL)
	{
	  *(result.left) = bdt_encode(cc, *(tree.left));
	}
	else
	{
	  result.left = NULL;
	}
	if(tree.right!=NULL)
	{
	  *(result.right) = bdt_encode(cc, *(tree.right));
	}
	else
	{
	  result.right=NULL ;
	}
	return result;
}

//encryption of a binary decision tree
bdt_ct bdt_encrypt(CryptoContext<DCRTPoly> cc, bdt_pt tree, const PublicKey<DCRTPoly> pk)
{
	bdt_ct result;
	result.root = cc->Encrypt(pk, tree.root);
	result.left = new bdt_ct();
	result.right = new bdt_ct();
	if(tree.left!=NULL)
	{
	  *(result.left) = bdt_encrypt(cc, *(tree.left), pk);
	}
	else
	{
	  result.left = NULL;
	}
	if(tree.right!=NULL)
	{
	  *(result.right) = bdt_encrypt(cc, *(tree.right), pk);
	}
	else
	{
	  result.right = NULL;
	}
	return result;
}

// sub-function for recursive de-serialization of an encrypted bdt
void ebdt_deserialize_switched(bdt_ct *tree, std::string name, int depth, int *tag)
{
	if (Serial::DeserializeFromFile(DATAFOLDER + "/" + name + std::to_string(*tag) + ".txt", tree->root, SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
    }
    std::cout << "a ciphertext has been deserialized." << std::endl;
    
    (*tag)++;
    
    tree->left = new bdt_ct();
	tree->right = new bdt_ct();
    
    if(depth !=1)
    {
		ebdt_deserialize_switched(tree->left, name, depth-1, tag);
		ebdt_deserialize_switched(tree->right, name, depth-1, tag);
	}
	else
	{
		tree->left = NULL;
		tree->right = NULL;
	}
}    

// de-serialization of an encrypted bdt (ebdt_deserialize_switched with value 0 at address tag)
void ebdt_deserialize(bdt_ct *tree, std::string name, int depth)
{
    int cpt = 0;
    int* tag = &cpt;
	ebdt_deserialize_switched(tree, name, depth, tag);
}

// homomorphic node-per-node substraction of two encrypted BDTs (the result being a new encrypted BDT)
bdt_ct bdt_evalSub(CryptoContext<DCRTPoly> cc, bdt_ct tree1, bdt_ct tree2)
{
	bdt_ct result;
	result.root = cc->EvalSub(tree1.root, tree2.root);
	result.left = new bdt_ct();
	result.right = new bdt_ct();
	if((tree1.left!=NULL) && (tree2.left!=NULL))
	{
	  *(result.left) = bdt_evalSub(cc, *(tree1.left), *(tree2.left));
	}
	else
	{
	  result.left = NULL;
	}
	if((tree1.right!=NULL) && (tree2.right!=NULL))
	{
	  *(result.right) = bdt_evalSub(cc, *(tree1.right), *(tree2.right));
	}
	else
	{
	  result.right = NULL;
	}
	return result;
}

// integers from 0 to N-1 in a binary form (this represents all the paths of a BT (without tags) of depth N)
std::vector<std::vector<int64_t>> abstract_paths(int N)
{
  std::vector<std::vector<int64_t>> result;
  for(int i=0;i<pow(2,N);i++)
  {
	 result.push_back({});
	 for(int j=0;j<N;j++)
	 {
		 result[i].push_back((int)(i/pow(2, N-1-j))%2);
	 }
  }
  return result;
}

// the same in reverse order
std::vector<std::vector<int64_t>> abstract_reversePaths(int N)
{
  std::vector<std::vector<int64_t>> result;
  for(int i=0;i<pow(2,N);i++)
  {
	 result.push_back({});
	 for(int j=0;j<N;j++)
	 {
		 result[i].push_back((int)(1-(int)(i/pow(2, N-1-j))%2));
	 }
  }
  return result;
}

// encoding abstract_paths(N)
std::vector<std::vector<Plaintext>> encoded_abstract_paths(CryptoContext<DCRTPoly> cc, int N)
{
	std::vector<std::vector<Plaintext>> result;
	for(int i=0;i<pow(2,N);i++)
	{
		result.push_back({});
		for(int j=0;j<N;j++)
		{
		   result[i].push_back(cc->MakePackedPlaintext({abstract_paths(N)[i][j]}));
		}
	}
	return result;
}

// the same in reverse order
std::vector<std::vector<Plaintext>> encoded_abstract_reversePaths(CryptoContext<DCRTPoly> cc, int N)
{
	std::vector<std::vector<Plaintext>> result;
	for(int i=0;i<pow(2,N);i++)
	{
		result.push_back({});
		for(int j=0;j<N;j++)
		{
		   result[i].push_back(cc->MakePackedPlaintext({abstract_reversePaths(N)[i][j]}));
		}
	}
	return result;
}

// encrypting abstract_paths(N)
std::vector<std::vector<Ciphertext<DCRTPoly>>> encrypted_abstract_paths(CryptoContext<DCRTPoly> cc, int N, const PublicKey<DCRTPoly> pk)
{
	std::vector<std::vector<Ciphertext<DCRTPoly>>> result;
	for(int i=0;i<pow(2,N);i++)
	{
		result.push_back({});
		for(int j=0;j<N;j++)
		{
		   result[i].push_back(cc->Encrypt(pk, encoded_abstract_paths(cc, N)[i][j]));
		}
	}
	return result;
}

// the same in reverse order
std::vector<std::vector<Ciphertext<DCRTPoly>>> encrypted_abstract_reversePaths(CryptoContext<DCRTPoly> cc, int N, const PublicKey<DCRTPoly> pk)
{
	std::vector<std::vector<Ciphertext<DCRTPoly>>> result;
	for(int i=0;i<pow(2,N);i++)
	{
		result.push_back({});
		for(int j=0;j<N;j++)
		{
		   result[i].push_back(cc->Encrypt(pk, encoded_abstract_reversePaths(cc, N)[i][j]));
		}
	}
	return result;
}

// paths of an encrypted bdt (as a vector of encrypted paths)
std::vector<std::vector<Ciphertext<DCRTPoly>>> bdt_evalPaths(CryptoContext<DCRTPoly> cc, bdt_ct tree, int depth)
{
	std::vector<std::vector<Ciphertext<DCRTPoly>>> result(pow(2, depth));
	std::vector<Ciphertext<DCRTPoly>> path(depth);
	for(int i=0; i<pow(2,depth);i++)
	{
		bdt_ct subtree = tree;
		for(int j=0; j<depth;j++)
		{
			result[i].push_back(Ciphertext<DCRTPoly>());
			result[i][j]=subtree.root;
			if(((subtree.right)!=NULL) && ((subtree.right)!=NULL))
			{
			    subtree = ((abstract_paths(depth)[i][j]) ? (*(subtree.right)) : (*(subtree.left)));
			}
		}
    }
    return result;
}

//encrypted result (with some slots with value -1 instead of 1) before the final homomorphic multiplications
std::vector<std::vector<Ciphertext<DCRTPoly>>> encrypted_result_before_mult(CryptoContext<DCRTPoly> cc, bdt_ct tree, bdt_ct data, int depth, const PublicKey<DCRTPoly> pk)
{
	int number_of_leaves = pow(2, depth);
	bdt_ct bdt_deltas = bdt_evalSub(cc, data, tree);
	std::vector<std::vector<Ciphertext<DCRTPoly>>> deltas = bdt_evalPaths(cc, bdt_deltas, depth);
	std::vector<std::vector<Ciphertext<DCRTPoly>>> result(number_of_leaves);

	for(int i=0; i<number_of_leaves; i++)
	{
		result[i] = std::vector<Ciphertext<DCRTPoly>>(depth);
		for(int j=0; j<depth; j++)
		{
		   result[i][j] = cc->EvalSub(cc->EvalMult(deltas[i][j], deltas[i][j]), encrypted_abstract_reversePaths(cc, depth, pk)[i][j]);
		}
	}
	return result;
} 

// homomorphic evaluation of the product of the elements of a vector
Ciphertext<DCRTPoly> evalGlobalProd(CryptoContext<DCRTPoly> cc, std::vector<Ciphertext<DCRTPoly>> ciphertexts)
{
	Ciphertext<DCRTPoly> result = ciphertexts[0];
	for(unsigned int i=1; i<ciphertexts.size(); i++)
	{
	   result = cc->EvalMult(result, ciphertexts[i]);
	}
	return result;
}

// evalGlobalProd on each element of a vector
std::vector<Ciphertext<DCRTPoly>> v_evalGlobalProd(CryptoContext<DCRTPoly> cc, std::vector<std::vector<Ciphertext<DCRTPoly>>> ciphertexts)
{
	std::vector<Ciphertext<DCRTPoly>> result;
	for(unsigned int i=0; i<ciphertexts.size(); i++)
	{
		result.push_back(evalGlobalProd(cc, ciphertexts[i]));
	}
	return result;
}

//final products. The output is a vector filled with 1 or -1 at the index associated to the output leave and 0 everywhere else.
std::vector<Ciphertext<DCRTPoly>> encrypted_result_after_mult(CryptoContext<DCRTPoly> cc, bdt_ct tree, bdt_ct data, int depth, const PublicKey<DCRTPoly> pk)
{
	return v_evalGlobalProd(cc, encrypted_result_before_mult(cc, tree, data, depth, pk));
}

//encoded powers of 2 in a reverse order (to get numerical values from their binary form)
std::vector<Plaintext> powersOf2(CryptoContext<DCRTPoly> cc, int N, const PublicKey<DCRTPoly> pk)
{
	std::vector<Plaintext> result;
	for(int i=0; i<N; i++)
	{
		result.push_back(cc->MakePackedPlaintext({(int) pow(2, N-1-i)}));
	}
	return result;
}

//encypted final result
Ciphertext<DCRTPoly> encrypted_result(CryptoContext<DCRTPoly> cc, bdt_ct tree, bdt_ct data, int depth, const PublicKey<DCRTPoly> pk)
{
	 std::vector<std::vector<Ciphertext<DCRTPoly>>> bin_result_at_some_slot;
	 std::vector<std::vector<Ciphertext<DCRTPoly>>> eap = encrypted_abstract_paths(cc, depth, pk);
	 std::vector<Ciphertext<DCRTPoly>> eram = encrypted_result_after_mult(cc, tree, data, depth, pk);
	 for(int i=0; i<pow(2, depth); i++)
	 {
		 bin_result_at_some_slot.push_back({});
		 for(int j=0; j<depth; j++)
		 {
			 bin_result_at_some_slot[i].push_back(cc->EvalMult(eap[i][j], eram[i]));
		 }
	 }
	
	
	std::vector<Ciphertext<DCRTPoly>> bin_result;
	for(int j=0; j<depth; j++)
	{
		bin_result.push_back(cc->Encrypt(pk, cc->MakePackedPlaintext({0})));
	}
	for(int i=0; i<pow(2,depth); i++)
	{
		for(int j=0; j<depth; j++)
		{
			bin_result[j] = cc->EvalAdd(bin_result[j], bin_result_at_some_slot[i][j]);
		}
	}
	
	//(here the -1 values are turned into 1 values in order to have each value at 0 or 1)
	for(int j=0; j<depth; j++)
	{
		bin_result[j] = cc->EvalMult(bin_result[j], bin_result[j]);
	}

	Ciphertext<DCRTPoly> result = cc->Encrypt(pk, cc->MakePackedPlaintext({0}));
	std::vector<Ciphertext<DCRTPoly>> acc;
	acc = std::vector<Ciphertext<DCRTPoly>>();
	for(int j=0; j<depth; j++)
	{		
		acc.push_back(cc->EvalMult(bin_result[j], powersOf2(cc, depth, pk)[j]));
		result = cc->EvalAdd(acc[j], result);
	}
	
	return result;
}

/////////////////////////////////////////////
//                                         //
//               |MAIN|                    //
//                                         //
/////////////////////////////////////////////

int main()
{
	//getting the depth
	int depth = calculateDepth(DATAFOLDER);
	//int depth = atoi(argv[1]);
	
	//getting the crypto-context and the the public keys
	CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(CRYPTOCONTEXT + "/cryptocontext.txt", cc, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << CRYPTOCONTEXT + "/cryptocontext.txt" << std::endl;
        return 1;
    }
    std::cout << "The cryptocontext has been deserialized." << std::endl;

    PublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk, SerType::BINARY) == false) {
        std::cerr << "Could not read public key" << std::endl;
        return 1;
    }
    std::cout << "The public key has been deserialized." << std::endl;
    
    std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
    if (!emkeys.is_open()) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
        return 1;
    }
    if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
        std::cerr << "Could not deserialize the eval mult key file" << std::endl;
        return 1;
    }
    std::cout << "Deserialized the eval mult keys." << std::endl;
    
    //getting the encrypted binary decision tree
    bdt_ct *p_tree = new bdt_ct();
    ebdt_deserialize(p_tree, "encrypted_tree", depth);
    bdt_ct encrypted_tree = *p_tree;
    
    //getting the encrypted client data
    bdt_ct *p_data = new bdt_ct();
    ebdt_deserialize(p_data, "encrypted_data", depth);
    bdt_ct encrypted_data = *p_data;
    
    //homomorphic evaluation of the binary decision tree on the client data
	Ciphertext<DCRTPoly> output_ciphertext = encrypted_result(cc, encrypted_tree, encrypted_data, depth, pk);
	
	//serializing the final result
	if (!Serial::SerializeToFile(RESULTSFOLDER + "/" + "output_ciphertext.txt", output_ciphertext, SerType::BINARY)) {
        std::cerr << "Error writing serialization of output ciphertext to output_ciphertext.txt" << std::endl;
        return 1;
    }
    std::cout << "The output ciphertext has been serialized." << std::endl;
    
    //////////////////////////////
    //////////////////////////////
      
    //main return value
    return 0;
}
