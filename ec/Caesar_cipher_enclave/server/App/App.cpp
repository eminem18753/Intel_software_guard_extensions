#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <string.h>
#include <vector>
#include <algorithm>
#include <iterator>
#include <cassert>
#include <sstream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#define PORT 10001

using namespace std;
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) 
{
    //printf("%s\n", str);
}
string caesarCipher(string source,int shift)
{
	string decrypt=source;
	for(int i=0;i<source.length();i++)
	{
		decrypt[i]-=shift;
	}
	return decrypt;
}
float calculatePredictionError(float *data,float *weights,int *groundTruth,int rowNumber,int colNumber)//to get the accuracy for training set
{
    float accuracy=0;
    for(int i=0;i<rowNumber;i++)
    {
	float predictResult=0;
	for(int j=0;j<colNumber;j++)
	{
		predictResult+=data[i*colNumber+j]*weights[j];
	}
	predictResult=1/(1+exp(-predictResult));
	//cout<<predictResult<<endl;
	if(predictResult>0.3)
	{
		predictResult=1;
	}
	else if(predictResult<=0.3)
	{
		predictResult=0;
	}
	if(predictResult==groundTruth[i])
	{
		accuracy++;
	}
    }
    accuracy=accuracy/rowNumber;
    return accuracy;
    /*
    float resultError=0;
    for(int i=0;i<rowNumber;i++)
    {
	float predictResult=0;
	for(int j=0;j<colNumber;j++)
	{
		predictResult+=data[i*colNumber+j]*weights[j];
	}
	resultError+=pow(groundTruth[i]-predictResult,2);
    }
    resultError/=rowNumber;
    resultError=sqrt(resultError);
    return resultError;
    */
}
int main(int argc, char const *argv[]) 
{
    srand(time(NULL));
    if(initialize_enclave(&global_eid,"enclave.token","enclave.signed.so")<0)
    {
	cout<<"Fail to initialize enclave."<<endl;
	return 1;
    }
    int randomNumber;
    sgx_status_t status=generate_random_number(global_eid,&randomNumber);
    //cout<<"test:"<<randomNumber<<endl;
    randomNumber=randomNumber+rand()%10000000;
    string randomResult=to_string(randomNumber);
    char randomKey[20]={0};
    strcpy(randomKey,randomResult.c_str());
    //tcp connection
    int server_fd,new_socket,valread,valwrite;
    vector<string> dataset;
    float* data;
    int* labels;
    unsigned int data_rows;
    unsigned int data_cols;
    unsigned int data_len;
    float* weights;

    struct sockaddr_in address;

    int flag=0;
    int opt=1;
    int addrlen=sizeof(address);

    char buffer[80]={0};
    char hello[30]="Hello, here is the server";

    if((server_fd=socket(AF_INET,SOCK_STREAM,0))==0)
    {
	perror("Socked failed");
	exit(EXIT_FAILURE);
    }

    if(setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR|SO_REUSEPORT,&opt,sizeof(opt)))
    {
	perror("setsockopt error");
	exit(EXIT_FAILURE);
    }

    address.sin_family=AF_INET;
    address.sin_addr.s_addr=INADDR_ANY;
    address.sin_port=htons(PORT);

    if(bind(server_fd,(struct sockaddr *)&address,sizeof(address))<0)
    {
	perror("bind failed");
	exit(EXIT_FAILURE);
    }
    if(listen(server_fd,3)<0)
    {
	perror("listen");
	exit(EXIT_FAILURE);
    }

    while(flag!=2&&(new_socket=accept(server_fd,(struct sockaddr *)&address,(socklen_t*)&addrlen))>-1)
    {
	valwrite=send(new_socket,randomKey,20,0);
	flag=2;
    }

    flag=0;
    while(flag!=2&&(new_socket=accept(server_fd,(struct sockaddr *)&address,(socklen_t*)&addrlen))>-1)
    {
        while(flag!=2)
        {
    	    bzero(buffer,80);
	    valread=recv(new_socket,buffer,80,0);

	    string temp(buffer);
	    temp=caesarCipher(temp,randomNumber%30);
	    cout<<temp<<endl;
	    if(valread<0)
	    {
	    	printf("Error reading from socket!\n");
	    }
    	    valwrite=send(new_socket,hello,80,0);
   	    if(valwrite<0)
	    {
	    	printf("Error writing to socket\n");
	    }
	    if(!temp.empty())
	    {
		flag=1;
		dataset.push_back(temp);
		//cout<<dataset.size()<<endl;
	    }
	    if(flag==1&&temp.empty())
	    {
		flag=2;
	    }
   	}
    }

	//test

	//cout<<dataset.size()<<endl;
	/*
	for(int i=0;i<dataset.size();i++)
	{
		cout<<dataset[i]<<endl;
	}
	*/
	//cout<<dataset.size()-1<<endl;

	//transfer the format of the dataset to fit the logistic regression in the Enclave
	data=(float*)malloc(sizeof(float)*(dataset.size()-1)*4);
	labels=(int*)malloc(sizeof(int)*(dataset.size()-1));

	int end=0;
	int index=1;
	int rowCount=0;
	while(index!=dataset.size())
	{
		istringstream iss(dataset[index]);
		string token;

		int colCount=0;
		while(getline(iss,token,','))
		{
			if(colCount<=3)
			{
				data[4*rowCount+colCount]=strtof((token).c_str(),0);
			}
			else if(colCount==4)
			{
				labels[rowCount]=atoi((token).c_str());
			}
			//cout<<token<<endl;
			colCount++;
		}

		rowCount++;
		index++;

		//test
		/*
		for(int i=0;i<4;i++)
		{
			cout<<data[i]<<" ";
		}
		cout<<labels[0]<<endl;
		*/
		//test
	}
	//test
	/*
	for(int i=0;i<(dataset.size()-1)*4;i++)
	{
		cout<<data[i]<<" ";
		if(i%4==3)
		{
			cout<<endl;
		}
	}
	for(int i=0;i<dataset.size()-1;i++)
	{
		cout<<labels[i]<<endl;
	}
	*/
    //tcp connection
    //use the enclave logistic regression

    const float lr=0.01;
    const int iter=100;
    weights=(float*)malloc(sizeof(float)*4);
    memset(weights,0,sizeof(float)*4);
    //float *returnWeights=(float*)malloc(sizeof(float)*4);
    //memset(returnWeights,0,sizeof(float)*4);
    sgx_status_t statusNow=train_logistic_regression1(global_eid,data,labels,lr,iter,rowCount,4,sizeof(float)*(dataset.size()-1)*4,weights);

    //cout<<statusNow<<endl;
    if(statusNow!=SGX_SUCCESS)
    {
	cout<<"noob"<<endl;
    }

    float result=calculatePredictionError(data,weights,labels,rowCount,4);
    //cout<<"Accuracy:"<<result<<endl;

    //test

    for(int i=0;i<4;i++)
    {
	cout<<"Weights:"<<weights[i]<<endl;
    }

    //pass the weights back
    flag=0;

    ostringstream oss1;
    oss1<<weights[0];
    ostringstream oss2;
    oss2<<weights[1];
    ostringstream oss3;
    oss3<<weights[2];
    ostringstream oss4;
    oss4<<weights[3];

    string weightString=oss1.str()+","+oss2.str()+","+oss3.str()+","+oss4.str();
    //cout<<weightString<<endl;
    char *weightToSend=(char*)malloc(sizeof(char)*weightString.size());
    strcpy(weightToSend,weightString.c_str());

    //test
    /*
    for(int i=0;i<weightString.size();i++)
    {
	    cout<<weightToSend[i];
    }
    */
    //test

    while(flag!=2&&(new_socket=accept(server_fd,(struct sockaddr *)&address,(socklen_t*)&addrlen))>-1)
    {
 	//for(int i=0;i<4;i++)
	//{
		valwrite=send(new_socket,weightToSend,weightString.size(),0);

		if(valwrite<0)
		{
			printf("Error writing to socket!\n");
		}
		valread=recv(new_socket,buffer,80,0);
		if(valread<0)
		{
			printf("Error reading from socket!\n");
		}
		/*
		bzero(buffer,80);
		valread=recv(new_socket,buffer,80,0);
		string temp(buffer);

		if(valread<0)
		{
			printf("Error reading from socket!\n");
		}

		valwrite=send(new_socket,hello,80,0);
		if(valwrite<0)
		{
			printf("Error writing to socket\n");
		}
		if(!temp.empty())
		{
			flag=1;
			dataset.push_back(temp);
			//cout<<dataset.size()<<endl;
		}
		if(flag==1&&temp.empty())
		{
			flag=2;
		}
		*/
	//}
	flag=2;
    }
    
    /*
    for(int i=0;i<4;i++)
    {
	cout<<"returnWeights:"<<returnWeights[i]<<endl;
    }
    */

    //cout<<"Success:"<<SGX_ERROR_OUT_OF_MEMORY<<endl;
    //test
    /*
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0)
    {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    int ptr;
    sgx_status_t status = generate_random_number(global_eid, &ptr);
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS)
    {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) 
    {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) 
    {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;
    */ 
    return 0;
}
