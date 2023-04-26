import socket
import sys
import encrypt

if __name__ == "__main__":

    if(len(sys.argv)!=2):
        print("argument fault")
        
        exit(0)

    # 設置主機和埠號
    host = '127.0.0.1'
    port = 5001

    # 建立套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 綁定主機和埠號
    server_socket.bind((host, port))

    # 監聽客戶端請求
    server_socket.listen(1)
    print(f"等待客戶端連接中...")

    # 等待客戶端連接
    client_socket, addr = server_socket.accept()
    print(f"客戶端 {addr[0]}:{addr[1]} 已連接")

    
    filename=sys.argv[1];

    # 獲取要傳輸的檔案名稱
    # filename = input("請輸入要傳輸的檔案名稱：")

    encrypt.encrypt(filename)

    # 讀取檔案內容
    with open(filename+".enc", 'rb') as f:
        file_data = f.read()


    # 將檔案大小和內容發送給客戶端
    client_socket.send(str(len(file_data)).encode())
    client_socket.send(file_data)

    print("檔案傳輸完成！")

    # 關閉套接字
    client_socket.close()
    server_socket.close()
