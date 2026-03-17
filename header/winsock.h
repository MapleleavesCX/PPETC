#pragma once
#include<iostream>
#include<WS2tcpip.h>
#include<string>

#pragma comment(lib, "ws2_32.lib")

#include"allheader.h"



using namespace std;
//收发消息的类
class SOCK {
public:
    SOCKET sock;
    string skey;
    string iv;
    
    SOCK() {
        // 创建套接字
        sock = socket(AF_INET, SOCK_STREAM, 0);
        skey = "";
        iv = "";
    }
    ~SOCK() {
        closesocket(sock);
    }
    //发消息
    bool sendto(string message);
    //收消息
    string receivefrom(size_t reclen = 268435456);

    //建立安全信道
    bool client_secure_channel_set(string tem_sk, string tem_pk);

    bool server_secure_channel_set();
    
    bool secure_sendto(string message);

    string secure_receivefrom(size_t reclen);

};

//用于建立客户端/服务端的类
class winsock {
private:
	SOCKET sock;
    WSADATA wsData;
    WORD version;

public:
    //初始化
    winsock();
    //作为客户端时：链接服务端
    bool linking_to_server(SOCK& serverSocket, string server_ip, int port = 8080);
    //作为服务端时：绑定监听端口
    bool set_server(int port = 8080);
    //作为服务端时：监听来访者
    bool listening_to_client(SOCK& clientSocket);




    ~winsock() {
        closesocket(sock);
        WSACleanup();
    }
};

winsock::winsock() {

    // 初始化 Winsock
    version = MAKEWORD(2, 2);
    int wsResult = WSAStartup(version, &wsData);
    if (wsResult != 0) {
        cerr << "Failed! Winsock Unable to initialize Winsock\n";
    }
    // 创建套接字
    sock = socket(AF_INET, SOCK_STREAM, 0);
}

bool winsock::linking_to_server(SOCK& serverSocket, string server_ip, int port) {

    // 连接到服务器
    cout << "*Linking to server...";
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);  // 使用服务器的端口号
    inet_pton(AF_INET, server_ip.c_str(), &(serverAddress.sin_addr));
    if (connect(serverSocket.sock, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cerr << "Failed! Unable to connect to server \n";
        return false;
    }
    else {
        cout << "Success!\n";
        return true;
    }
}

bool winsock::set_server(int port) {
    // 绑定服务器地址和端口
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);  // 使用指定的端口号
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        return false;
    }
    else {
        return true;
    }
}

bool winsock::listening_to_client(SOCK& clientSocket) {

    // 开始监听连接请求
    cout << "Listening...\n";
    sockaddr_in client_ip;
    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "failed\n";
        return false;
    }
    else {
        // 等待客户端连接
        int clientAddressSize = sizeof(client_ip);
        clientSocket.sock = accept(sock, (sockaddr*)&client_ip, &clientAddressSize);
        if (clientSocket.sock == INVALID_SOCKET) {
            cerr << "Unable to accept client connections\n";
            return false;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_ip.sin_addr), clientIP, INET_ADDRSTRLEN);

        cout << "*Received a visit request*\nVisitor IP address：" << clientIP << endl;  // 显示来访者IP地址

        return true;
    }
}

bool SOCK::client_secure_channel_set(string tem_sk, string tem_pk) {

    string req_pk = "REQ" + tem_pk;

    //发送
    int err = send(sock, req_pk.c_str(), req_pk.size() + 1, 0);
    if (err == SOCKET_ERROR) {
        cout << "Send message Error!\n";
        return false;
    }

    //接收
    char rec[8192];
    ZeroMemory(rec, 8192);
    err = recv(sock, rec, 8192, 0);
    if (err <= 0) {
        cout << "Receive message Error!\n";
        return false;
    }
    string key_iv_ctext = rec;


    if (key_iv_ctext.substr(0, 3) != "YES")
    {
        return false;
    }
    vector<string> c1c2c3 = {
        key_iv_ctext.substr(3, 128),
        key_iv_ctext.substr(131, key_iv_ctext.size() - 195),
        key_iv_ctext.substr(key_iv_ctext.size() - 64, 64) };
    string key_iv_ptext;
    if (!sm2_dec(key_iv_ptext, tem_sk, c1c2c3))
    {
        return false;
    }
    skey = key_iv_ptext.substr(0, 16);
    iv = key_iv_ptext.substr(16, 16);
    return true;
}

bool SOCK::server_secure_channel_set() {
    skey = randstr(0, 255, 16);
    iv = randstr(0, 255, 16);

    //接收
    char rec[8192];
    ZeroMemory(rec, 8192);
    int err = recv(sock, rec, 8192, 0);
    if (err <= 0) {
        cout << "Receive message Error!\n";
        return false;
    }
    string req_pk = rec;


    if (req_pk.substr(0, 3) != "REQ")
    {
        return false;
    }
    vector<string> pk = { req_pk.substr(3, 64), req_pk.substr(67, 64) };
    vector<string> c1c2c3;
    string key_iv = skey + iv;
    sm2_enc(c1c2c3, key_iv, pk);

    //发送
    string sendm = "YES" + c1c2c3[0] + c1c2c3[1] + c1c2c3[2];
    err = send(sock, sendm.c_str(), sendm.size() + 1, 0);
    if (err == SOCKET_ERROR) {
        cout << "Send message Error!\n";
        return false;
    }


    return true;
}




bool SOCK::sendto(string message) {
    int err = send(sock, message.c_str(), message.size() + 1, 0);
    if (err == SOCKET_ERROR) {
        cout << "Send message Error!\n";
        return false;
    }
    else {
        return true;
    }
}

string SOCK::receivefrom(size_t reclen) {
    size_t finallen = reclen * 2 + 1;
    char* rec = new char[finallen];
    //char rec[8192];
    ZeroMemory(rec, finallen);
    int err = recv(sock, rec, finallen, 0);
    if (err <= 0) {
        cout << "Receive message Error!\n";
        delete[] rec;
        return "";
    }
    else {
        string message = rec;
        delete[] rec;
        return message;
    }
}



bool SOCK::secure_sendto(string message) {
    

    string mac = sm3_mac(skey, message);
    string sendbit;
    if (!sm4work(CTR_enc, sendbit, message + mac, skey, iv))
        return false;
    /*printf("send: \n");
    for (size_t i = 0; i < sendbit.size(); i++) {
        uint8_t xx = sendbit[i];
        printf("%X", xx);
    }
    printf("\n\n");*/
    int err = send(sock, sendbit.c_str(), sendbit.size() + 1, 0);
    if (err == SOCKET_ERROR) {
        cout << "Send message Error!\n";
        return false;
    }
    else {
        return true;
    }
}

string SOCK::secure_receivefrom(size_t reclen) {

    size_t finallen = reclen + 32;
    string recebit(finallen, 0);
    char* rec = new char[finallen];
    //char rec[1024];
    ZeroMemory(rec, finallen);
    int err = recv(sock, rec, finallen, 0);
    if (err <= 0) {
        cout << "Receive message Error!\n";
        /*printf("rec: ");
        for (size_t i = 0; i < reclen; i++) {
            uint8_t xx = rec[i];
            printf("%X", xx);
        }
        printf("\n\n");*/
        delete[] rec;
        return "";
    }
    for (size_t i = 0; i < finallen; i++) {
        uint8_t x = rec[i];
        recebit[i] = x;
    }

    delete[] rec;
    string m_mac;
    if (!sm4work(CTR_dec, m_mac, recebit, skey, iv))
    {
        cout << "Dec Error!\n";
        return "";
    }

    size_t l = m_mac.size();
    string mac = m_mac.substr(l - 32, 32);
    string message = m_mac.substr(0, l - 32);

    if (!sm3_verimac(skey, message, mac))
    {
        cout << "veriMAC Error!\n";
        return "";
    }
    return message;
}