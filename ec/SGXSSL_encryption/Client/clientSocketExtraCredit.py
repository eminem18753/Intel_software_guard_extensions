#!/usr/bin/python3
import socket
import csv
import math
import OpenSSL.crypto as crypto

HOST='seclab-enclave-2.cs.illinois.edu'
PORT=10001

t = crypto.PKey()
print(t)
t.generate_key(crypto.TYPE_RSA, 4096)
t_key = crypto.dump_publickey(crypto.FILETYPE_ASN1, t)
print(len(t_key))
print([hex(i) for i in t_key])



y=socket.socket(socket.AF_INET,socket.SOCK_STREAM) #use IPv4 and TCP protocol

def read_csv(file_name):
    result = []
    with open(file_name,'r') as csvfile:
        for row in csv.reader(csvfile, delimiter=' ', quotechar='|'):
            result.append(''.join(row))
    return result

dataRead = read_csv('dataset1.csv')

try:
    y.connect((HOST,PORT))
except Exception as e:
    print("Connect error")
    print(e)
key_asn = y.recv(4096)
y.close()

print([hex(i) for i in key_asn])


key = crypto.load_publickey(crypto.FILETYPE_ASN1, key_asn)
print(key.bits())

codeText=publickey.encrypt(flat_data,526)


print(codeText)
#encrypt the data
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
try:
    s.connect((HOST,PORT))
except Exception:
    print("Connect error second")

for dataTemp in dataRead:
    print(dataTemp)
    s.send(dataTemp)
    data=s.recv(80)

s.close()
#extra credits

#Get the weights from the server
r=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

try:
    r.connect((HOST,PORT))
except Exception:
    print("Connect error")

weights=r.recv(80)

weightsParse=weights.split(',',4);

weightAcquired=[0,0,0,0]

for index in range(len(weightsParse)):
    weightFloat = weightsParse[index]
    weightAcquired[index]=float(weightFloat)

testSet=read_csv('testset.csv')

testData=[[]]*(len(testSet)-1)
finalDatas=[[]]*(len(testSet)-1)
finalLabels=[]

for index in range(len(testSet)):
    testTemp = testSet[index]
    dataTemp = testTemp.split(',',5);
    testData[index-1]=dataTemp
    finalDatas[index-1]=[float(dataTemp[0]),float(dataTemp[1]),float(dataTemp[2]),float(dataTemp[3])]
    finalLabels.append(int(dataTemp[4]))

#make predictions
predictionProbability=[]
predictionResult=[]
for i in range(len(testSet)-1):
    tempResult=0
    for j in range(4):
        tempResult+=finalDatas[i][j]*weightAcquired[j]
    tempResult=1/(1+math.exp(-tempResult))
    predictionProbability.append(tempResult)
    if tempResult<0.4:
        predictionResult.append(0)
    else:
        predictionResult.append(1)

#calculate accuracy
accuracy=float(0)
for i in range(len(testSet)-1):
    print(finalLabels[i])
    if predictionResult[i]==finalLabels[i]:
        accuracy=accuracy+1

accuracy=accuracy/(len(testSet)-1)
print(accuracy)
