	client.rar contains a client_side code(for transferring only 1 dataset).  It uses a cipher similar to Caesar(but not restricted to only alphabet).  We hard code a large number in the enclave and use a random number generator to generate another number in App.cpp.  The key is the sum of the 2 numbers, and it is then sent to client, so client will use the key to encrypt the dataset.(symmetric encryption)
steps:
1.go to server and run makefile($make)
2../app
3.go to the client side and run python clientSocket.py
4.you will see the encoded dataset and the final testset accuracy calculated with the model retrieved by the server.