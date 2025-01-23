# AES Encryption/Decryption Project

此專案展示了如何使用 OpenSSL 庫進行 AES 加密和解密操作。

## 依賴項目

- g++
- OpenSSL

## 編譯

使用以下命令編譯專案：

```sh
make all
```

## 運行

編譯完成後，使用以下命令運行程式：

```sh
./aes
```

## 文件結構

- `aes.cpp` 和 `aes.hpp`：包含 AES 加密和解密的實現。
- `main.cpp`：測試 AES 加密和解密功能的主程式。
- `makefile`：編譯專案的 makefile。

## 功能

- 設置 AES 密鑰
- 生成和設置 IV（初始化向量）
- 加密和解密字符串
- 打印 IV

## 注意事項

- 確保在系統中安裝了 OpenSSL 庫。
- 使用正確的密鑰長度（128、192 或 256 位）。
