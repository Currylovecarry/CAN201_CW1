import socket
import struct
import json
import hashlib
import time
import os

#复用服务器中的函数
#1.获取文件的md5值,
#2.打包成 TCP 数据包
#3.从 TCP 流中解析包

def get_file_md5(filename):
    """
    Get MD5 value for big file
    :param filename:
    :return:
    """
    m = hashlib.md5()
    with open(filename, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)
    return m.hexdigest()

def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data:
    :param bin_data:
    :return:
        The complete binary packet
    """
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data

def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''
    while len(bin_data) < 16:
        data_rec = conn.recv(8)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data

# ------------------------------------------ Task 2 ---------------------------------------------------

def task2_login(client_socket, student_id):
    """
    Execute Task 2 login process and return the Token.
    """
    print("\n--- Executing Task 2: Login ---")

    # 1. Prepare login information according to protocol
    username = student_id
    password = hashlib.md5(student_id.encode('utf-8')).hexdigest()

    print(f"Username (student_id): {username}")
    print(f"Password (MD5(Student ID)): {password[:10]}...")

    # 2. Construct login request
    login_request_json = {#第一次上传的登录的json格式
        "type": "AUTH",
        "operation": "LOGIN",
        "direction": "REQUEST",
        "username": username,
        "password": password
    }

    # 3. Send request and get response
    print("Sending login request...")
    login_packet = make_packet(login_request_json, None)#将用户名和密码还有登录信息打包成TCP数据包
    client_socket.sendall(login_packet)#发送数据包到服务器

    print("Waiting for server response...")
    json_response, bin_response = get_tcp_packet(client_socket)#从TCP流中解析包，得到json_response

    if json_response is None:
        print("Login failed: No response from server.")
        return None

    # 4. Process response
    print(f"Server response: {json.dumps(json_response, indent=2)}")#打印服务器返回的json_response，方便调试

    if json_response.get('status') == 200:#在server.py中，STEP_service登录成功返回status 200
        token = json_response.get('token')#也是在server.py中STEP_service，登录成功会返回token 这个token的值也是在server定义好的
        if token:
            print("Login successful! (Task 2 completed)")
            print(f"Received Token: {token[:15]}...")
            return token
        else:
            print("Login failed: Server returned 200 OK but no token included.")
            return None
    else:
        print(f"Login failed: {json_response.get('status_msg')}")
        return None


#------------------------------------------- Task 3 -----------------------------------------------

def task3_upload_file(client_socket, token, file_path):
    """
    Execute Task 3 file upload process.
    """
    print(f"\n--- Executing Task 3: Upload File ---")
    print(f"Preparing to upload: {file_path}")#文件路径

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File does not exist {file_path}")
        return

    # --- Phase 1: Request upload permission (FILE/SAVE) ---
    print("\nPhase 1: Requesting upload permission (FILE/SAVE)...")

    file_size = os.path.getsize(file_path)#获取文件大小
    file_key = os.path.basename(file_path)#获取文件名

    save_request_json = {#保存请求的json数据格式。主要是发给服务器获得上传计划
        "type": "FILE",
        "operation": "SAVE",
        "direction": "REQUEST",
        "token": token,
        "key": file_key,
        "size": file_size
    }

    client_socket.sendall(make_packet(save_request_json))#发送上传请求数据包
    json_response, bin_response = get_tcp_packet(client_socket)#从TCP流中解析包

    if json_response is None or json_response.get('status') != 200:
        print(f"Phase 1 failed: {json_response.get('status_msg', 'No response')}")
        return

    # Parse upload plan 包含block_size, total_block, key
    try:
        block_size = json_response['block_size']
        total_block = json_response['total_block']
        server_key = json_response['key']
        print("Phase 1 succeeded. Received upload plan:")
        print(f"  Key: {server_key}")
        print(f"  Block Size: {block_size} bytes")
        print(f"  Total Blocks: {total_block}")
    except KeyError:
        print("Phase 1 failed: Missing key fields in server response.")
        print(json.dumps(json_response, indent=2))
        return

    # --- Phase 2: Upload data blocks (FILE/UPLOAD) ---按照服务器在 Phase 1 返回的上传计划，将文件分块上传，并在每块上传后等待服务器确认，确保文件数据完整可靠地传输到服务器。
    print("\nPhase 2: Starting block-by-block upload (FILE/UPLOAD)...")

    try:
        with open(file_path, 'rb') as f:# open file in binary read mode
            for i in range(total_block):
                print(f"  Uploading block {i + 1}/{total_block}...", end=' ')

                file_chunk = f.read(block_size)
                if not file_chunk:
                    print("Error: File read ended prematurely, insufficient data block!")
                    return

                upload_request_json = {#上传文件块的json数据格式
                    "type": "FILE",
                    "operation": "UPLOAD",# upload command so server.py STEP_service will call handle_file_upload, json_response will have md5 field
                    "direction": "REQUEST",
                    "token": token,
                    "key": server_key,
                    "block_index": i
                }

                # Send JSON and binary file chunk
                client_socket.sendall(make_packet(upload_request_json, file_chunk))

                # Wait for confirmation of each block
                json_response, bin_response = get_tcp_packet(client_socket)

                if json_response is None or json_response.get('status') != 200:
                    print(f"\n Phase 2 failed (Block {i}): {json_response.get('status_msg', 'No response')}")
                    return

                print("OK.")

                # --- Phase 3: Verification (MD5) ---
                if 'md5' in json_response:
                    print("\nPhase 3: Received final confirmation from server (MD5 verification)...")
                    server_md5 = json_response['md5']
                    print(f"  Server computed MD5: {server_md5}")

                    # Client computes local file MD5
                    client_md5 = get_file_md5(file_path)
                    print(f"  Client computed MD5: {client_md5}")

                    if server_md5.lower() == client_md5.lower():
                        print("\nMD5 match! (Task 3 completed)")
                        print("File successfully uploaded and verified.")
                    else:
                        print("\n MD5 mismatch! File may be corrupted.")
                    return  # Task completed

    except Exception as e:
        print(f"\n Phase 2 encountered an unexpected error: {e}")

#-------------------------------------------- main -----------------------------------------------------

def main():
    print("--- STEP Protocol Client ---")

    # 1. Get user input for student_id
    student_id = input("Please enter your Student ID: ")
    if not student_id:
        print("Error: Student ID cannot be empty. Exiting program.")
        return

    ## Use default server IP and port
    server_ip = '127.0.0.1'
    server_port = 1379

    print(f"\nAttempting to connect to {server_ip}:{server_port}...")

    client_socket = None
    try:
        # 2. Establish TCP connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        print("Connection successful!")

        # 3. Execute Task 2: Login
        token = task2_login(client_socket, student_id)

        # 4. If login is successful, prompt the user to input the file path for upload
        if token:
            file_to_upload = input("Please enter the path of the file to upload (e.g., test.txt): ")
            if not file_to_upload:
                print("Error: No file specified for upload. Exiting program.")
                return

        # 5. # 5. Execute Task 3: Upload File
            task3_upload_file(client_socket, token, file_to_upload)
        else:
            print("Unable to proceed with file upload due to login failure.")

    except socket.error as e:
        print(f"\nSocket error: {e}")
        print("Please ensure the server is running and the IP and port are correct.")
    except Exception as e:
       print(f"\nUnexpected error: {e}")
    finally:
        if client_socket:
            client_socket.close()
        print("\nConnection closed.")

if __name__ == '__main__':
    main()