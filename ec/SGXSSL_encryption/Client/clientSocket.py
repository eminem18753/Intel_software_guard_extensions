import socket
import csv
import math

HOST='seclab-enclave-2.cs.illinois.edu'
PORT=10001

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) #use IPv4 and TCP protocol

dataRead=[]


#read the dataset

with open('dataset1.csv','rb') as csvfile:
	spamreader=csv.reader(csvfile,delimiter=' ',quotechar='|')

	for row in spamreader:
		tempRow=''.join(row)
		dataRead.append(tempRow)
	#print(dataRead)
#Start to connect to the socket and check if succeed
try:
	s.connect((HOST,PORT))
	print("Server port "+str(PORT)+" connected!")
except Exception:
	print("Warning, server port "+str(PORT)+" not connected!")

#Start for message sending
for dataTemp in dataRead:
	print(dataTemp)
	s.send(dataTemp)
	data=s.recv(80)

s.close()

#Get the weights from the server
r=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

try:
	r.connect((HOST,PORT))
except Exception:
	print("Connect error")

weights=r.recv(80)

weightsParse=weights.split(',',4);

weightAcquired=[0,0,0,0]
index=0

for weightFloat in weightsParse:
	weightAcquired[index]=float(weightFloat)
	index=index+1
#testSet
testSet=[]
with open('testset.csv','rb') as csvfile:
	spamreader=csv.reader(csvfile,delimiter=' ',quotechar='|')

	for row in spamreader:
		tempRow=''.join(row)
		testSet.append(tempRow)
		#print(row)

index=0
testData=[[]]*(len(testSet)-1)
finalDatas=[[]]*(len(testSet)-1)
finalLabels=[]
#print(len(testSet)-1)
for testTemp in testSet:
	dataTemp=[]
	if index>0:
		dataTemp=testTemp.split(',',5);
		testData[index-1]=dataTemp
		finalDatas[index-1]=[float(dataTemp[0]),float(dataTemp[1]),float(dataTemp[2]),float(dataTemp[3])]
		finalLabels.append(int(dataTemp[4]))
	index=index+1

#for data in weightsParse:
#	print(data)

#make predictions
predictionProbability=[]
predictionResult=[]
for i in range(len(testSet)-1):
	tempResult=0
	for j in range(4):
		tempResult+=finalDatas[i][j]*weightAcquired[j]
	tempResult=1/(1+math.exp(-tempResult))
	predictionProbability.append(tempResult)
	#print(tempResult)
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
