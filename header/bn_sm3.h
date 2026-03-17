#pragma once

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include<vector>
#include <string>
#include <iostream>

using namespace std;

//输入为bit流，输出为string类型的bit流（共32个字符），
//需要用可视化函数转换为用字符串表示的十六进制字符串
string sm3(const string input) {
    EVP_MD_CTX* mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    string ss(32, 0x00);
    for (int i = 0; i < 32; i++) {
        ss[i] = hash[i];
    }
    return ss;
}

//mac
string sm3_mac(string key, string input) {
    string key_inpt = key + input;
    string output = sm3(key_inpt);
    return output;
}

// 验证mac
bool sm3_verimac(string key, string message, string mac) {
    string key_m = key + message;
    string mac_ = sm3(key_m);
    if (mac == mac_)
        return true;
    else
        return false;
}