import socket
import struct
import json
import hashlib
import time
import os  # 导入 os 模块来处理文件路径和大小

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
    执行 Task 2 登录流程并返回 Token。
    """
    print("\n--- 正在执行 Task 2: 登录 ---")

    # 1. 按协议准备登录信息
    username = student_id
    password = hashlib.md5(student_id.encode('utf-8')).hexdigest()

    print(f"用户名 (student_id): {username}")
    print(f"密码 (MD5(Student ID)): {password[:10]}...")

    # 2. 构建登录请求
    login_request_json = {
        "type": "AUTH",
        "operation": "LOGIN",
        "direction": "REQUEST",
        "username": username,
        "password": password
    }

    # 3. 发送请求并获取响应
    print("正在发送登录请求...")
    login_packet = make_packet(login_request_json, None)
    client_socket.sendall(login_packet)

    print("正在等待服务器响应...")
    json_response, _ = get_tcp_packet(client_socket)

    if json_response is None:
        print("登录失败：未收到服务器响应。")
        return None

    # 4. 处理响应
    print(f"服务器响应: {json.dumps(json_response, indent=2)}")

    if json_response.get('status') == 200:
        token = json_response.get('token')
        if token:
            print("登录成功! (Task 2 完成)")
            print(f"获取到的 Token: {token[:15]}...")
            return token
        else:
            print("登录失败：服务器返回 200 OK 但未包含 token。")
            return None
    else:
        print(f"登录失败: {json_response.get('status_msg')}")
        return None


#------------------------------------------- Task 3 -----------------------------------------------

def task3_upload_file(client_socket, token, file_path):
    """
    执行 Task 3 文件上传流程。
    """
    print(f"\n--- 正在执行 Task 3: 上传文件 ---")
    print(f"准备上传: {file_path}")

    # 检查文件是否存在
    if not os.path.exists(file_path):
        print(f"错误：文件不存在 {file_path}")
        return

    # --- Phase 1: 请求上传 (FILE/SAVE) ---
    print("\nPhase 1: 请求上传许可 (FILE/SAVE)...")

    file_size = os.path.getsize(file_path)
    file_key = os.path.basename(file_path)  # 使用文件名作为 key

    save_request_json = {
        "type": "FILE",
        "operation": "SAVE",
        "direction": "REQUEST",
        "token": token,
        "key": file_key,
        "size": file_size
    }

    client_socket.sendall(make_packet(save_request_json))
    json_response, _ = get_tcp_packet(client_socket)

    if json_response is None or json_response.get('status') != 200:
        print(f"Phase 1 失败: {json_response.get('status_msg', '无响应')}")
        return

    # 解析上传计划
    try:
        block_size = json_response['block_size']
        total_block = json_response['total_block']
        server_key = json_response['key']
        print("Phase 1 成功。获取上传计划:")
        print(f"  Key: {server_key}")
        print(f"  Block Size: {block_size} 字节")
        print(f"  Total Blocks: {total_block}")
    except KeyError:
        print("Phase 1 失败：服务器响应中缺少上传计划的关键字段。")
        print(json.dumps(json_response, indent=2))
        return

    # --- Phase 2: 上传数据块 (FILE/UPLOAD) ---
    print("\nPhase 2: 开始逐块上传 (FILE/UPLOAD)...")

    try:
        with open(file_path, 'rb') as f:
            for i in range(total_block):
                print(f"  正在上传 block {i + 1}/{total_block}...", end=' ')

                file_chunk = f.read(block_size)
                if not file_chunk:
                    print("错误：文件读取提前结束，数据块不足！")
                    return

                upload_request_json = {
                    "type": "FILE",
                    "operation": "UPLOAD",
                    "direction": "REQUEST",
                    "token": token,
                    "key": server_key,
                    "block_index": i
                }

                # 发送 JSON 和 二进制文件块
                client_socket.sendall(make_packet(upload_request_json, file_chunk))

                # 等待每一块的确认
                json_response, _ = get_tcp_packet(client_socket)

                if json_response is None or json_response.get('status') != 200:
                    print(f"\n Phase 2 失败 (Block {i}): {json_response.get('status_msg', '无响应')}")
                    return

                print("OK.")

                # --- Phase 3: 验证 (MD5) ---
                # 检查服务器对*最后一块*的响应是否包含 MD5
                if 'md5' in json_response:
                    print("\nPhase 3: 收到服务器最终确认 (MD5 验证)...")
                    server_md5 = json_response['md5']
                    print(f"  服务器计算的 MD5: {server_md5}")

                    # 客户端计算本地文件的 MD5
                    client_md5 = get_file_md5(file_path)
                    print(f"  客户端计算的 MD5: {client_md5}")

                    if server_md5.lower() == client_md5.lower():
                        print("\nMD5 匹配! (Task 3 完成)")
                        print("文件已成功上传并验证。")
                    else:
                        print("\n MD5 不匹配! 文件可能已损坏。")
                    return  # 任务完成

    except Exception as e:
        print(f"\n Phase 2 发生意外错误: {e}")

#-------------------------------------------- main -----------------------------------------------------

def main():
    print("--- STEP 协议客户端 ---")

    # 1. 获取用户输入 student_id
    student_id = input("请输入你的 Student ID: ")
    if not student_id:
        print("错误：Student ID 不能为空。程序退出。")
        return

    # 使用默认服务器 IP 和端口
    server_ip = '127.0.0.1'
    server_port = 1379

    print(f"\n正在尝试连接到 {server_ip}:{server_port}...")

    client_socket = None
    try:
        # 2. 建立 TCP 连接
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, server_port))
        print("连接成功！")

        # 3. 执行 Task 2: 登录
        token = task2_login(client_socket, student_id)

        # 4. 登录成功后再让用户输入上传文件路径
        if token:
            file_to_upload = input("请输入要上传的文件的路径 (例如: test.txt): ")
            if not file_to_upload:
                print("错误：未指定上传文件。程序退出。")
                return

            # 5. 执行 Task 3: 上传文件
            task3_upload_file(client_socket, token, file_to_upload)
        else:
            print("因登录失败，无法继续执行文件上传。")

    except socket.error as e:
        print(f"\nSocket 错误: {e}")
        print("请确保服务器正在运行，并且 IP 和端口正确。")
    except Exception as e:
        print(f"\n发生意外错误: {e}")
    finally:
        if client_socket:
            client_socket.close()
            print("\n连接已关闭。")

if __name__ == '__main__':
    main()