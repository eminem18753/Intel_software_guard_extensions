	client.rar contains a client_side code(for transferring only 1 dataset).  It uses a cipher similar to Caesar(but not restricted to only alphabet).  We hard code it to be 16 so that server should also use 16 as the key to decipher it.(symmetric encryption)
steps:
1.go to server and run makefile($make)
2../app
3.go to the client side and run python clientSocket.py
4.you will see the encoded dataset and the final testset accuracy calculated with the model retrieved by the server.