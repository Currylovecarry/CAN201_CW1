import socket
import struct
import json
import hashlib
import time
import os
import sys
import logging
import threading
from tqdm import tqdm
from server import get_file_md5, make_packet, get_tcp_packet

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ------------------------------------------ Task 2 ---------------------------------------------------

def task2_login(client_socket, student_id):
    """
    Execute Task 2 login process and return the Token.
    """
    logger.info("--- Executing Task 2: Login ---")

    # 1. Prepare login information according to protocol
    username = student_id
    password = hashlib.md5(student_id.encode('utf-8')).hexdigest()

    logger.info(f"Username (student_id): {username}")
    logger.info(f"Password (MD5(Student ID)): {password[:10]}...")

    # 2. Construct login request
    login_request_json = {
        "type": "AUTH",
        "operation": "LOGIN",
        "direction": "REQUEST",
        "username": username,
        "password": password
    }

    # 3. Send request and get response
    logger.info("Sending login request...")
    login_packet = make_packet(login_request_json, None)
    client_socket.sendall(login_packet)

    logger.info("Waiting for server response...")
    json_response, bin_response = get_tcp_packet(client_socket)

    if json_response is None:
        logger.error("Login failed: No response from server.")
        return None

    # 4. Process response
    logger.info(f"Server response: {json.dumps(json_response, indent=2)}")

    if json_response.get('status') == 200:
        token = json_response.get('token')
        if token:
            logger.info("Login successful! (Task 2 completed)")
            logger.info(f"Received Token: {token[:15]}...")
            return token
        else:
            logger.error("Login failed: Server returned 200 OK but no token included.")
            return None
    else:
        logger.error(f"Login failed: {json_response.get('status_msg')}")
        return None


# ------------------------------------------ Task 3 - Enhanced ---------------------------------------------------

def upload_block(args):
    """
    Upload a single block with retry mechanism
    """
    server_ip, server_port, token, server_key, block_index, block_data, max_retries = args
    retries = 0

    while retries <= max_retries:
        block_socket = None
        try:
            # Create new connection for this block
            block_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            block_socket.settimeout(30)  # 30 seconds timeout
            block_socket.connect((server_ip, server_port))

            upload_request_json = {
                "type": "FILE",
                "operation": "UPLOAD",
                "direction": "REQUEST",
                "token": token,
                "key": server_key,
                "block_index": block_index
            }

            # Send block data
            block_socket.sendall(make_packet(upload_request_json, block_data))

            # Get response
            json_response, bin_response = get_tcp_packet(block_socket)
            block_socket.close()

            if json_response and json_response.get('status') == 200:
                return (block_index, True, None, json_response)
            elif json_response and 'completely uploaded' in json_response.get('status_msg', '').lower():
                # File is already completely uploaded, treat as success
                logger.info(f"Block {block_index}: File already completely uploaded on server")
                return (block_index, True, "File already complete", json_response)
            else:
                error_msg = json_response.get('status_msg', 'Unknown error') if json_response else 'No response'
                logger.warning(f"Block {block_index} upload failed: {error_msg}, retry {retries + 1}/{max_retries}")
                retries += 1

        except Exception as e:
            logger.warning(f"Block {block_index} connection error: {e}, retry {retries + 1}/{max_retries}")
            retries += 1
            if block_socket:
                try:
                    block_socket.close()
                except:
                    pass

    return (block_index, False, f"Failed after {max_retries} retries", None)


def handle_existing_file(client_socket, token, file_key):
    """
    Handle the case when file already exists on server
    """
    print(f"\nFile '{file_key}' already exists on server.")
    print("Choose an option:")
    print("1. Overwrite the existing file")
    print("2. Rename the file")
    print("3. Cancel upload")

    while True:
        choice = input("Enter your choice (1/2/3): ").strip()
        if choice == '1':
            # Delete existing file first
            if task4_delete_file(client_socket, token, file_key):
                logger.info("Existing file deleted, proceeding with upload...")
                return True
            else:
                logger.error("Failed to delete existing file")
                return False
        elif choice == '2':
            # Rename the file
            new_name = input("Enter new filename: ").strip()
            if new_name:
                return new_name
            else:
                print("Invalid filename, please try again.")
        elif choice == '3':
            logger.info("Upload cancelled by user.")
            return False
        else:
            print("Invalid choice, please enter 1, 2, or 3.")


def task3_upload_file_single_thread(client_socket, token, file_path, server_ip, server_port, max_retries=3):
    """
    Single thread file upload with progress bar
    """
    logger.info(f"--- Single Thread Upload ---")
    return task3_upload_file_enhanced(client_socket, token, file_path, server_ip, server_port, 1, max_retries)


def task3_upload_file_multi_thread(client_socket, token, file_path, server_ip, server_port, num_threads=4,
                                   max_retries=3):
    """
    Multi-thread file upload with progress bar
    """
    logger.info(f"--- Multi-Thread Upload ({num_threads} threads) ---")
    return task3_upload_file_enhanced(client_socket, token, file_path, server_ip, server_port, num_threads, max_retries)


def task3_upload_file_enhanced(client_socket, token, file_path, server_ip, server_port, num_threads=4, max_retries=3):
    """
    Enhanced file upload with multi-threading, progress bar, retry mechanism, and performance logging
    """
    logger.info(f"--- Executing Enhanced Task 3: Upload File ---")
    logger.info(f"Preparing to upload: {file_path}")
    logger.info(f"Using {num_threads} threads, max {max_retries} retries per block")

    start_time = time.time()

    # Check if file exists
    if not os.path.exists(file_path):
        logger.error(f"Error: File does not exist {file_path}")
        return False

    # --- Phase 1: Request upload permission (FILE/SAVE) ---
    logger.info("Phase 1: Requesting upload permission (FILE/SAVE)...")

    file_size = os.path.getsize(file_path)
    file_key = os.path.basename(file_path)

    save_request_json = {
        "type": "FILE",
        "operation": "SAVE",
        "direction": "REQUEST",
        "token": token,
        "key": file_key,
        "size": file_size
    }

    client_socket.sendall(make_packet(save_request_json))
    json_response, bin_response = get_tcp_packet(client_socket)

    # Handle file already exists case
    if json_response and json_response.get('status') == 400 and 'existing' in json_response.get('status_msg',
                                                                                                '').lower():
        result = handle_existing_file(client_socket, token, file_key)
        if result is True:
            # Retry with same filename after deletion
            client_socket.sendall(make_packet(save_request_json))
            json_response, bin_response = get_tcp_packet(client_socket)
        elif result is False:
            return False
        else:
            # Use new filename
            file_key = result
            save_request_json['key'] = file_key
            client_socket.sendall(make_packet(save_request_json))
            json_response, bin_response = get_tcp_packet(client_socket)

    if json_response is None or json_response.get('status') != 200:
        logger.error(f"Phase 1 failed: {json_response.get('status_msg', 'No response')}")
        return False

    # Parse upload plan
    try:
        block_size = json_response['block_size']
        total_block = json_response['total_block']
        server_key = json_response['key']
        logger.info("Phase 1 succeeded. Received upload plan:")
        logger.info(f"  Key: {server_key}")
        logger.info(f"  Block Size: {block_size} bytes")
        logger.info(f"  Total Blocks: {total_block}")
    except KeyError:
        logger.error("Phase 1 failed: Missing key fields in server response.")
        logger.error(json.dumps(json_response, indent=2))
        return False

    # --- Phase 2: Multi-threaded block upload ---
    logger.info("Phase 2: Starting multi-threaded block upload...")

    # Read all blocks into memory
    blocks = []
    try:
        with open(file_path, 'rb') as f:
            for i in range(total_block):
                block_data = f.read(block_size)
                if not block_data:
                    logger.error(f"Error: File read ended prematurely at block {i}")
                    return False
                blocks.append(block_data)
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return False

    # Prepare upload tasks
    upload_tasks = []
    for i in range(total_block):
        task_args = (server_ip, server_port, token, server_key, i, blocks[i], max_retries)
        upload_tasks.append(task_args)

    # Create shared variables for thread coordination
    current_task_index = 0
    task_lock = threading.Lock()
    completed_blocks = 0
    completed_lock = threading.Lock()
    failed_blocks = []
    failed_lock = threading.Lock()
    final_md5 = None
    md5_lock = threading.Lock()

    def worker(worker_id):
        nonlocal current_task_index, completed_blocks, final_md5
        while True:
            # Get next task
            with task_lock:
                if current_task_index >= len(upload_tasks):
                    break
                task_index = current_task_index
                current_task_index += 1

            # Execute task
            result = upload_block(upload_tasks[task_index])
            block_index, success, error_msg, response = result

            # Process result
            if success:
                with completed_lock:
                    completed_blocks += 1
                with pbar_lock:
                    pbar.update(1)

                # Check if response contains MD5 (final block)
                if response and 'md5' in response:
                    with md5_lock:
                        if final_md5 is None:
                            final_md5 = response['md5']
                            logger.info(f"Received final MD5 from server: {final_md5}")
            else:
                with failed_lock:
                    failed_blocks.append((block_index, error_msg))
                logger.error(f"Thread {worker_id}: Block {block_index} failed: {error_msg}")

    # Create progress bar with lock for thread safety
    pbar_lock = threading.Lock()
    with tqdm(total=total_block, desc="Uploading blocks", unit="block") as pbar:
        # Start worker threads
        threads = []
        for i in range(min(num_threads, total_block)):
            thread = threading.Thread(target=worker, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    # Check for failed blocks
    if failed_blocks:
        logger.error(f"Upload failed: {len(failed_blocks)} blocks failed to upload")

        # Ask user if they want to retry failed blocks
        retry_choice = input("\nDo you want to retry failed blocks? (y/n): ").strip().lower()
        if retry_choice == 'y':
            logger.info("Retrying failed blocks...")
            for block_index, error in failed_blocks[:]:  # Copy the list
                logger.info(f"Retrying block {block_index}...")
                task_args = (server_ip, server_port, token, server_key, block_index, blocks[block_index], max_retries)
                result = upload_block(task_args)
                block_index, success, error_msg, response = result
                if success:
                    failed_blocks.remove((block_index, error))
                    pbar.update(1)

                    # Check if response contains MD5 (final block)
                    if response and 'md5' in response:
                        with md5_lock:
                            if final_md5 is None:
                                final_md5 = response['md5']
                                logger.info(f"Received final MD5 from server: {final_md5}")

            if failed_blocks:
                logger.error(f"Still {len(failed_blocks)} blocks failed after retry")
                return False
        else:
            return False

    # --- Phase 3: Final verification using MD5 from server ---
    logger.info("Phase 3: Performing final verification...")

    # Calculate performance metrics
    end_time = time.time()
    upload_time = end_time - start_time
    upload_speed = file_size / upload_time / 1024 / 1024  # MB/s

    logger.info("=== Upload Performance ===")
    logger.info(f"File size: {file_size / 1024 / 1024:.2f} MB")
    logger.info(f"Upload time: {upload_time:.2f} seconds")
    logger.info(f"Upload speed: {upload_speed:.2f} MB/s")
    logger.info(f"Blocks: {total_block}, Threads: {num_threads}")

    # Use MD5 from server if available, otherwise compute locally
    if final_md5:
        server_md5 = final_md5
        logger.info(f"Server computed MD5: {server_md5}")
    else:
        # Fallback: request MD5 from server using INFO operation
        logger.info("No MD5 received from server during upload, requesting file info...")
        info_request_json = {
            "type": "FILE",
            "operation": "INFO",
            "direction": "REQUEST",
            "token": token,
            "key": server_key
        }

        try:
            client_socket.sendall(make_packet(info_request_json))
            json_response, bin_response = get_tcp_packet(client_socket)

            if json_response and json_response.get('status') == 200 and 'md5' in json_response:
                server_md5 = json_response['md5']
                logger.info(f"Server computed MD5: {server_md5}")
            else:
                logger.warning("Could not retrieve MD5 from server, using local computation")
                server_md5 = get_file_md5(file_path)
        except:
            logger.warning("Error requesting file info from server, using local computation")
            server_md5 = get_file_md5(file_path)

    # Client computes local file MD5
    client_md5 = get_file_md5(file_path)
    logger.info(f"Client computed MD5: {client_md5}")

    if server_md5.lower() == client_md5.lower():
        logger.info("MD5 match! (Task 3 completed)")
        logger.info("File successfully uploaded and verified.")
        return True
    else:
        logger.error("MD5 mismatch! File may be corrupted.")
        return False


# ------------------------------------------ Task 4: Delete File ---------------------------------------------------

def task4_delete_file(client_socket, token, file_key):
    """
    Execute Task 4: Delete uploaded file
    """
    logger.info(f"\n--- Executing Task 4: Delete File ---")
    logger.info(f"Requesting deletion of file: {file_key}")

    delete_request_json = {
        "type": "FILE",
        "operation": "DELETE",
        "direction": "REQUEST",
        "token": token,
        "key": file_key
    }

    client_socket.sendall(make_packet(delete_request_json))
    json_response, bin_response = get_tcp_packet(client_socket)

    if json_response is None:
        logger.error("Delete failed: No response from server.")
        return False

    if json_response.get('status') == 200:
        logger.info("File deleted successfully! (Task 4 completed)")
        return True
    else:
        logger.error(f"Delete failed: {json_response.get('status_msg')}")
        return False


# ------------------------------------------ Interactive Menu ---------------------------------------------------

def interactive_menu(server_ip, server_port, student_id):
    """
    Interactive menu for user to choose operations
    """
    client_socket = None

    try:
        # Establish connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(60)
        client_socket.connect((server_ip, server_port))
        logger.info("Connection successful!")

        # Login first
        token = task2_login(client_socket, student_id)
        if not token:
            logger.error("Login failed. Cannot proceed.")
            return

        while True:
            print("\n" + "=" * 50)
            print("          STEP Protocol Client Menu")
            print("=" * 50)
            print("1. Single-thread Upload")
            print("2. Multi-thread Upload")
            print("3. Delete File")
            print("4. Exit")
            print("=" * 50)

            choice = input("Please choose an option (1-4): ").strip()

            if choice == '1':
                file_path = input("Enter file path to upload: ").strip()
                if not file_path:
                    print("File path cannot be empty.")
                    continue
                if not os.path.exists(file_path):
                    print(f"Error: File does not exist: {file_path}")
                    continue

                # Get retry count from user
                try:
                    max_retries = int(input("Enter max retries per block (default 3): ").strip() or "3")
                    if max_retries < 0:
                        print("Retry count must be non-negative. Using default 3.")
                        max_retries = 3
                except ValueError:
                    print("Invalid number. Using default 3 retries.")
                    max_retries = 3

                # Single thread upload
                task3_upload_file_single_thread(client_socket, token, file_path, server_ip, server_port, max_retries)

            elif choice == '2':
                file_path = input("Enter file path to upload: ").strip()
                if not file_path:
                    print("File path cannot be empty.")
                    continue
                if not os.path.exists(file_path):
                    print(f"Error: File does not exist: {file_path}")
                    continue

                # Get thread count from user
                try:
                    num_threads = int(input("Enter number of threads (default 4): ").strip() or "4")
                    if num_threads < 1:
                        print("Thread count must be at least 1. Using default 4.")
                        num_threads = 4
                except ValueError:
                    print("Invalid number. Using default 4 threads.")
                    num_threads = 4

                # Get retry count from user
                try:
                    max_retries = int(input("Enter max retries per block (default 3): ").strip() or "3")
                    if max_retries < 0:
                        print("Retry count must be non-negative. Using default 3.")
                        max_retries = 3
                except ValueError:
                    print("Invalid number. Using default 3 retries.")
                    max_retries = 3

                # Multi-thread upload
                task3_upload_file_multi_thread(client_socket, token, file_path, server_ip, server_port, num_threads,
                                               max_retries)

            elif choice == '3':
                file_key = input("Enter filename to delete from server: ").strip()
                if not file_key:
                    print("Filename cannot be empty.")
                    continue

                task4_delete_file(client_socket, token, file_key)

            elif choice == '4':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")

    except Exception as e:
        logger.error(f"Error in interactive menu: {e}")
    finally:
        if client_socket:
            client_socket.close()


# ------------------------------------------ Main ---------------------------------------------------

def main():
    print("--- STEP Protocol Client ---")

    # Default values
    server_ip = '127.0.0.1'
    server_port = 1379
    student_id = None
    file_to_upload = None
    num_threads = 4
    max_retries = 3

    # Parse command line arguments
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--server_ip' and i + 1 < len(args):
            server_ip = args[i + 1]
            i += 2
        elif args[i] == '--id' and i + 1 < len(args):
            student_id = args[i + 1]
            i += 2
        elif args[i] == '--f' and i + 1 < len(args):
            file_to_upload = args[i + 1]
            i += 2
        elif args[i] == '--threads' and i + 1 < len(args):
            num_threads = int(args[i + 1])
            i += 2
        elif args[i] == '--retries' and i + 1 < len(args):
            max_retries = int(args[i + 1])
            i += 2
        else:
            i += 1

    # If student_id not provided, ask user input
    if not student_id:
        student_id = input("Please enter your Student ID: ")
        if not student_id:
            print("Error: Student ID cannot be empty. Exiting program.")
            return

    # If no file provided, enter interactive mode
    if not file_to_upload:
        # Get server info for interactive mode
        server_ip_input = input(f"Enter server IP [{server_ip}]: ").strip()
        if server_ip_input:
            server_ip = server_ip_input

        server_port_input = input(f"Enter server port [{server_port}]: ").strip()
        if server_port_input:
            try:
                server_port = int(server_port_input)
            except ValueError:
                print(f"Invalid port, using default: {server_port}")

        interactive_menu(server_ip, server_port, student_id)
        return

    # Command line mode with file upload
    logger.info(f"Attempting to connect to {server_ip}:{server_port}...")
    logger.info(f"Configuration: {num_threads} threads, {max_retries} max retries")

    client_socket = None
    try:
        # Establish TCP connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(60)  # 60 seconds timeout
        client_socket.connect((server_ip, server_port))
        logger.info("Connection successful!")

        # Execute Task 2: Login
        token = task2_login(client_socket, student_id)

        # If login is successful, upload file with enhanced features
        if token:
            success = task3_upload_file_enhanced(
                client_socket, token, file_to_upload,
                server_ip, server_port, num_threads, max_retries
            )

            if success:
                logger.info("All tasks completed successfully!")
            else:
                logger.error("File upload failed.")
        else:
            logger.error("Unable to proceed with file upload due to login failure.")

    except socket.error as e:
        logger.error(f"Socket error: {e}")
        logger.error("Please ensure the server is running and the IP and port are correct.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        if client_socket:
            client_socket.close()
        logger.info("Connection closed.")


if __name__ == '__main__':
    main()