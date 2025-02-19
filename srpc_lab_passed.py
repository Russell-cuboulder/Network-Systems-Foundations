import json
import socket
import time
from multiprocessing import Process
import os
import sys
import struct


###
### TASK FOR THE LAB
# Implement the following functions:
#    string recv_message(conn)
#    server_program()
# See skeleton code for specifics of each function
#
# NOTE 1: DO NOT modify any methods other than recv_message(conn) and server_program(). The autograder may not award you full points if you change the original implementation of the other provided methods.
#
# NOTE 2: Ensure that your implementation of server_program() is properly accepting connections, sending responses to requests, and closing connections.
#           If you submit this assignment and the autograder takes more than a couple minutes to respond
#           and then returns an error similar to: 'Platform Error: We're experiencing some technical difficulties'
#           an improper implementation could be causing the autograder to time out waiting for responses from your code.
#           

dictionary = {}

# { obj: name }
# { obj: name, val: dictionary }
# value can be arbitrary 
def get(params):
    name = params["obj"]
    entry = dictionary.get(name)
    retval = {"obj":name, "val":entry}
    return retval

# {obj:name, val: dictionary}
# {obj:name, response:response}
def put(params):
    name = params["obj"]
    val = params["val"]
    dictionary[name] = val
    retval = {"obj":name, "response":"ok"}
    return retval


# {func: func, params: params}
# {func: func, response: response}
def make_call(msg):
    func = msg["func"]
    param = msg["params"]
    if (func == "GET"): 
        return {"func":"GET", "response":get(param)}
    elif (func == "PUT"):
        return {"func":"PUT", "response":put(param)}
    else:
        return {"func":func, "response":"ERROR - Function doesn't exist"}



# TO IMPLEMENT
# See send_message(conn, json_dict) to see how it sends
# def recv_message(conn):
   # conn is the client_socket (returned from socket.socket() or socket.accept()) 
   # Read in 8 bytes.  The header is packed as two 4 byte integers (use struct.unpack("ii", header))
   #  The two ints are the version and the data length
   #  Read in dataLen bytes.  Use the decode() function to decode the received bytes.
   #  The string will be a json string
   #  return a json dictionary (use json.loads(json_string))

def recv_message(conn):
    # Read header (8 bytes: two 4-byte integers)
    header = conn.recv(8)
    if not header:
        return None  # Connection closed

    # Unpack header into version and data length
    version, data_len = struct.unpack("ii", header)

    # Read the JSON data
    json_data = b""
    while len(json_data) < data_len:
        chunk = conn.recv(data_len - len(json_data))
        if not chunk:
            return None  # Connection closed
        json_data += chunk

    # Decode the JSON data and return as a dictionary
    return json.loads(json_data.decode())





  # return None # Replace this line


def send_message(conn, json_dict):
    # version, len
    # JSON BLOB

    json_blob = json.dumps(json_dict)
    len_blob = len(json_blob)
    hdr = struct.pack("ii", 1, len_blob)
    conn.send(hdr)
    conn.send(json_blob.encode())  # send message


# TO IMPLEMENT
# see client_do_single_call for connecting to the program
#def server_program():
    # get the hostname (we're running client and server on same machine)
    # host = socket.gethostname()
    # port = 4444  
    # Open a socket, on the above port, and listen for multiple connections (5 is reasonable)
    # Be sure to set the SO_REUSEADDR socket option so the port can be re-used (prior to binding the socket)  
    #   server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # When connected, receive a message (with recv_message(conn))
    # pass the received message to make_call(json_dict)
    # Then send back a message with either of the following using send_message(conn, json_dict):
       # {"status": "ERROR"}
       # {"status":"OK", "response":retval}
    # Then close that connection, and continue listening for more connections

def server_program():
    # Get the hostname and port
    host = socket.gethostname()
    port = 4444

    # Create a socket object
    server_socket = socket.socket()

    # Set the SO_REUSEADDR option to allow reusing the port
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the host and port
    server_socket.bind((host, port))

    # Listen for incoming connections (up to 5 clients)
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}...")

    while True:
        # Accept a connection from a client
        conn, address = server_socket.accept()
        print(f"Connection from: {address}")

        try:
            # Receive the message from the client
            json_dict = recv_message(conn)
            if not json_dict:
                print("No data received. Closing connection.")
                conn.close()
                continue

            # Process the message using make_call
            response = make_call(json_dict)

            # Send the response back to the client
            send_message(conn, {"status": "OK", "response": response})

        except Exception as e:
            # Handle any errors and send an error response
            print(f"Error: {e}")
            send_message(conn, {"status": "ERROR"})

        finally:
            # Close the connection
            conn.close()
            print(f"Connection with {address} closed.")





    return None


def client_do_single_call(call):
    host = socket.gethostname()  # client and server are both running on same host
    port = 4444  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    send_message(client_socket, call)

    json_dict = recv_message(client_socket)

    client_socket.close()  # close the connection
    return json_dict




# This is a wrapper for client_do_single_call
# If local == True it will perform the call locally, and return as the server would
# Else it will call client_do_singl_call which will package the call up 
#   in a message and send to the server, and return the response.
def client_do_single_call_wrapper(mode, call):
    if (mode == "LOCAL"):
        retval = make_call(call)
        return {"status":"OK", "response":retval}
    else: 
        return client_do_single_call(call)    


# This provides example test cases for the client program
# each call is wrapped to provide a way to see what responses you should get from the Server 
# by using a local call instead of a client / server.  
def test_client_program(mode):
    # Should be Error
    call1 = {"func":"GET", "params":{"obj":"ABC"}}
    ret1 = client_do_single_call_wrapper(mode, call1)
    print("Call:" + str(call1))
    print("Ret:" + str(ret1))
    
    call2 = {"func":"PUT", "params":{"obj":"HELLO", "val":"WORLD"}}
    ret2 = client_do_single_call_wrapper(mode, call2)
    print("Call:" + str(call2))
    print("Ret:" + str(ret2))


    call3 = {"func":"PUT", "params":{"obj":"ABC", "val":{"val1":111, "val2": 222}}}
    ret3 = client_do_single_call_wrapper(mode, call3)
    print("Call:" + str(call3))
    print("Ret:" + str(ret3))

    call4 = {"func":"PUT", "params":{"obj":"DEF", "val":{"val1":333, "val2": 444}}}
    ret4 = client_do_single_call_wrapper(mode, call4)
    print("Call:" + str(call4))
    print("Ret:" + str(ret4))

    call5 = {"func":"GET", "params":{"obj":"ABC"}}
    ret5 = client_do_single_call_wrapper(mode, call5)
    print("Call:" + str(call5))
    print("Ret:" + str(ret5))

    call6 = {"func":"GET", "params":{"obj":"DEF"}}
    ret6 = client_do_single_call_wrapper(mode, call6)
    print("Call:" + str(call6))
    print("Ret:" + str(ret6))


# The program can be run in 1 of three modes for testing
# LOCAL - no sockets are created, just call the functions directly
# CLIENT - run as a Client, so will make calls
# SERVER - run as a server, so will receive calls
# BOTH - run both the client and server, using python multi-processing
# One way to run this within VS Code:
# - Open VS Code Terminal window
# - Navigate to part1-srpc folder
# - Execute 'python3 srpc_lab.py <mode>'
def main(argv):
    if (len(argv) != 2):
        print("srpc_lab.py <mode>")
        print("mode is one of LOCAL, CLIENT, SERVER, BOTH")
        return -1
    mode = argv[1]
    print(mode)
    if (mode == "LOCAL" or mode == "CLIENT"):
        test_client_program(mode)
    elif (mode == "SERVER"):
        server_program()
    elif (mode == "BOTH"):
        pServer = Process(target=server_program, args=())
        pServer.start()
        time.sleep(1)
        pClient = Process(target=test_client_program, args=('CLIENT',))
        pClient.start()
        pClient.join()
        pServer.terminate()
        pServer.join()
    else:
        print("srpc_lab.py <mode>")
        print("mode is one of LOCAL, CLIENT, SERVER, BOTH")
        return -1
    return 0


if __name__ == "__main__":
   retval = main(sys.argv)
