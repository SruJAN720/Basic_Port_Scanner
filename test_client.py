import socket
host = "127.0.0.1"
port = 65432
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
    s.connect((host,port))
    print("Connected to a server successfully")
    while True:
        message = input("Enter a message to send to the client. Type quit to exit:")
        if(message == "quit"):
            break
        s.sendall(message.encode())
        data = s.recv(1024)
        print("Server response:",data.decode())