	The code "Enclave.cpp" in the Enclave folder can initialize the logistic enclave and generate a public key. What's more, it enables App.cpp to get the public key length so as to make the encryption of the dataset work, there is also an private key decryption function in the enclave to decrypt the dataset sent from the client side, the scheme is stated as follows, which is more secure than the previous 2.
	I decide to let the client request a public key first, and then the enclave will generate a public/private key pair.  The public one will be sent to the client, where the client will use it to encrypt the dataset.  While, the server will later call the enclave to use the private key stored inside to decrypt the dataset first, and then send it to the logistic regression function, hoIver it doesn't work yet. I've tried to modify the client code from python to c, nevertheless.

The functions that implement our ideas are in "Enclave.cpp" in the Enclave folder and "App.cpp" in the App folder.