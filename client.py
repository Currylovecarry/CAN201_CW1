import socket
import struct
import json
import hashlib
import time
import os
import sys
from server import get_file_md5, make_packet, get_tcp_packet
#复用服务器中的函数
#1.获取文件的md5值,
#2.打包成 TCP 数据包
#3.从 TCP 流中解析包
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
            print(f"Token: {token}")
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
    start_time = time.time()

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

                #进度条显示
                progress = (i + 1) / total_block
                bar_len = 30
                filled_len = int(bar_len * progress)
                bar = '█' * filled_len + '-' * (bar_len - filled_len)
                print(f"\rUploading: |{bar}| {progress*100:6.2f}%", end='')

                # 最后一块时换行
                if i + 1 == total_block:
                    print()

                # --- Phase 3: Verification (MD5) ---
                if 'md5' in json_response:
                    print("\nPhase 3: Received final confirmation from server (MD5 verification)...")
                    server_md5 = json_response['md5']
                    print(f"  Server computed MD5: {server_md5}")

                    # Client computes local file MD5
                    client_md5 = get_file_md5(file_path)
                    print(f"  Client computed MD5: {client_md5}")

                    if server_md5.lower() == client_md5.lower():
                        end_time = time.time()
                        elapsed_time_ms = (end_time - start_time) * 1000
                        print(f"Total upload time: {elapsed_time_ms:.0f} ms")
                        print("\nMD5 match! (Task 3 completed)")
                        print("File successfully uploaded and verified.")
                    else:
                        print("\n MD5 mismatch! File may be corrupted.")
                    return  # Task completed

    except Exception as e:
        print(f"\n Phase 2 encountered an unexpected error: {e}")

def delete_file(client_socket, token, filename=None):
    """
    Delete file from server.
    If filename is not provided, ask user interactively.
    """
    # Interactive input (only when not provided via command-line arguments)
    if not filename:
        filename = input("Please enter the name of the file to delete (Press Enter to cancel): ").strip()
        if not filename:
            print("No filename provided. Cancelled.")
            return

    payload = {
        "type": "FILE",
        "operation": "DELETE",
        "direction": "REQUEST",
        "token": token,
        "key": filename
    }

    client_socket.sendall(make_packet(payload))

    json_response, _ = get_tcp_packet(client_socket)

    if json_response is None:
        print("[x] No response from server (connection closed?)")
        return

    status = json_response.get('status') or json_response.get('status_code') or 0
    status_msg = json_response.get('status_msg') or json_response.get('message') or ''
    if status == 200:
        print(f" Delete succeeded: {status_msg or 'OK'}")
    else:
        print(f" Delete failed ({status}): {status_msg}")

#-------------------------------------------- main -----------------------------------------------------

def main():
    print("--- STEP Protocol Client ---")

    # Default values
    server_ip = '127.0.0.1'
    server_port = 1379
    student_id = None
    file_to_upload = None
    file_to_delete = None
    interactive_mode = False

    # Parse command line arguments for --server_ip, --id, --f
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] in ('--server_ip', '-s') and i + 1 < len(args):
            server_ip = args[i + 1]
            i += 2
        elif args[i] in ('--id', '-i') and i + 1 < len(args):
            student_id = args[i + 1]
            i += 2
        elif args[i] in ('--f', '-f') and i + 1 < len(args):
            file_to_upload = args[i + 1]
            i += 2
        elif args[i] in ('--d', '-d') and i + 1 < len(args):
            file_to_delete = args[i + 1]
            i += 2
        else:
            i += 1

    # If no parameters are provided, the interactive mode will be entered.
    if not args:
        interactive_mode = True
        student_id = input("Please enter your Student ID: ").strip()
        if not student_id:
            print("Error: Student ID cannot be empty. Exiting program.")
            return

        mode = input("Choose operation: [U]Upload / [D]Delete ? (press Enter to cancel): ").strip().lower()
        if mode == 'u':
            file_to_upload = input("Enter file path to upload: ").strip()
            if not file_to_upload:
                print("No file path entered. Exiting.")
                return
        elif mode == 'd':
            file_to_delete = input("Enter filename to delete: ").strip()
            if not file_to_delete:
                print("No filename entered. Exiting.")
                return
        else:
            print("Cancelled by user.")
            return
    #参数模式
    if not student_id:
        student_id = input("Please enter your Student ID: ").strip()
        if not student_id:
            print("Error: Student ID cannot be empty. Exiting program.")
            return

    if not file_to_upload and not file_to_delete:
        print("Error: You must specify either --f <file> to upload or --d <file> to delete.")
        return

    print(f"\nAttempting to connect to {server_ip}:{server_port}...")

    client_socket = None
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        print("Connection successful!")

        # Execute Task 2: Login
        token = task2_login(client_socket, student_id)
        if not token:
            print("Login failed, cannot proceed.")
            return

        # --- 上传逻辑 ---
        if file_to_upload:
            task3_upload_file(client_socket, token, file_to_upload)

            # 只有命令行模式且同时传了 --d 才自动删除
            if not interactive_mode and file_to_delete:
                print(f"\n-- Both upload and delete specified. Deleting '{file_to_delete}'...")
                delete_file(client_socket, token, file_to_delete)

        if file_to_delete:
            # 交互模式下只有用户主动选择删除才执行
            if not interactive_mode or (interactive_mode and not file_to_upload):
                print(f"\nExecuting delete operation for '{file_to_delete}'...")
                delete_file(client_socket, token, file_to_delete)

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