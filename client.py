import socket
import decrypt

if __name__ == "__main__":
    # 設置主機和埠號
    host = '127.0.0.1'
    port = 5001

    # 建立套接字
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 連接服務器
    client_socket.connect((host, port))
    print(f"已連接到 {host}:{port}")

    # 接收檔案大小
    file_size = int(client_socket.recv(1024).decode())
    print(f"檔案大小為 {file_size} bytes")

    # 接收檔案內容
    file_data = b''
    while len(file_data) < file_size:
        data = client_socket.recv(1024)
        file_data += data


    # 將檔案寫入本地檔案中
    # filename = input("請輸入儲存檔案的名稱：")
    filename="raw"
    with open(filename+".enc", 'wb') as f:
        f.write(file_data)

    print("檔案傳輸完成！")

    # 關閉套接字
    client_socket.close()

    decrypt.decrypt("raw.enc")
