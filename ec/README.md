	I've implemented 4 levels of secure codes, which shows the development of our ideas!

*************************************************************************
1.Caesar_cipher (Simple security, it works)
	The "Caesar_cipher" folder contains the code for client that encrypts the dataset with caesar_cipher, and the code for server that decrypts the dataset with caesar_cipher.  In this case, even if the man in the middle gets chance to acquire the plaintext, they still have to defeat our cipher so as to steal the data.
*************************************************************************
2.Caesar_cipher_enclave (Medium security, it works)
	The "Caesar_cipher_enclave" folder contains a random key generated as the sum of the number in the Enclave(hardcoded) and the result of a random generator in App.cpp, this makes the decryption even harder for man in the middle attack.
*************************************************************************
3.SGXSSL_public_private_key(High Security, finish all the functions and the server side, not yet work)
	I use public/private key pair generated in the enclave to secure the communication. I first send the public key to the client side upon request, and requires the client side to use the public key to encrypt the dataset.  The server side than uses an enclave function call to decrypt the dataset in the server and then use the decrypted data to feed in the training_logistic_regression.
	If the code in clientSocket.py can use the key received from the server side to encrypt the dataset, then this code should work, and provide security for enclave logistic regression.
*************************************************************************
4.SGXSSL_encryption(Best Security, finish all the functions, not yet work)
	I've also come up with our best idea of even better security for communication. The step is like this.
steps to take:
a.Client connects to server and requests public key.
b.On server, I call into the enclave to request a public key.
c.Enclave generates a random public/private key pair, stores both in memory and returns the public key.
d.Server replies to client with public key. 
e.Client uses public key to encrypt dataset to server.
f.Enclave decrypts using stored private key."
	HoIver, this still can be modified(since in this case, server can still swap out the public key), I can make the scheme even more secure if I can get a trusted remote server to place our secret key.
	I've made the enclave public/private key pair generation function, getPublicKeyLengthFunction and the encrptedTrainingLogisticRegression function in the enclave.  HoIver, I can not make it wrong due to some hairy data format problems.
	The concept is stated as above, this is the best way I can think of to secure the enclave machine learning.
