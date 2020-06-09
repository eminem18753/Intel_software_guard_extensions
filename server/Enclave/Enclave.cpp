#include "Enclave_t.h"
#include "math.h"
#include <stdio.h>

int generate_random_number() 
{
    ocall_print("Processing random number generation...");
    return 45;
}

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
