#include "Enclave_t.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sgx_trts.h>

int generate_random_number() 
{
    ocall_print("Processing random number generation...");
    return 45;
}

RSA * context = NULL;
BIGNUM * BN = NULL;
EVP_PKEY * keys = NULL;
int public_key_length = 0;
unsigned char * public_key = NULL;
const int bits = 4096;
int init_lib = 1;
const int RAND_SEED_LENGTH = 16;

void init_logistic_enclave() {
	if (init_lib) {
		OPENSSL_init_crypto(0, NULL); // From Intel SGX SSL Library Linux Developer Guide
	}
	if (context != NULL) {
		return;
	}
	unsigned char SEED[RAND_SEED_LENGTH];
	sgx_read_rand(SEED, RAND_SEED_LENGTH);
	RAND_seed(SEED, RAND_SEED_LENGTH);
	context = RSA_new();
	BN = BN_new();
	BN_set_word(BN, RSA_F4);
	RSA_generate_key_ex(context, bits, BN, NULL);
	keys = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(keys, context);
	public_key_length = i2d_PublicKey(keys, &public_key); // Based off example code from: https://github.com/intel/intel-sgx-ssl/blob/master/Linux/sgx/test_app/enclave/TestEnclave.cpp	
}

int get_public_key_length() {
	return public_key_length;
}

void get_public_key(unsigned char * ptr, int len) {
	if (len < 0 || public_key_length < 0) {
		return;
	}
	memcpy(ptr, public_key, (len < public_key_length ? len : public_key_length) + 1);
}

void decrypt(int data_len,unsigned char *encrypted_data,unsigned char *decrypted)
{
	RSA_private_decrypt(data_len,encrypted_data,decrypted,context,RSA_PKCS1_PADDING);
}
void destroy_logistic_enclave() {
	if (context == NULL) {
		return;
	}
	RSA_free(context);
	BN_free(BN);
	free(public_key);
	EVP_PKEY_free(keys);
	context = NULL;
	public_key = NULL;
	BN = NULL;
	public_key_length = -1;
}

//void train_logistic_regression1(unsigned char * encrypted_data,const float lr,const int iter,const unsigned int data_rows,const unsigned int data_cols,const unsigned int data_len,float* weights)
void train_logistic_regression1(float* data,int* labels,const float lr,const int iter,const unsigned int data_rows,const unsigned int data_cols,const unsigned int data_len,float* weights)
{
	float *diffs=(float*)malloc(sizeof(float)*data_rows);
	
	for(int x=0;x<iter;++x)
	{
		for(int r=0;r<data_rows;++r)
		{
			float z=0.0f;
			for(int c=0;c<data_cols;++c)
			{
				z+=weights[c]*data[r*data_cols+c];
			}
			z=1.0f/(1.0f+(float)exp(-z));
			diffs[r]=z-labels[r];
		}
		for(int c=0;c<data_cols;++c)
		{
			float grad=0.0f;
			for(int r=0;r<data_rows;++r)
			{
				grad+=data[r*data_cols+c]*diffs[r];
			}
			grad=grad*lr/data_rows;
			weights[c]-=grad;
		}
	}
}
