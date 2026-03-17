#ifndef _RING_SIG_
#define _RING_SIG_

#include <openssl/bn.h>
#include "rsa.h"
#include <cstdlib>
#include <vector>
#include <random>
#include <ostream>
using namespace std;
const size_t station_num = 256;
const static size_t rand_len = 512; // 随机数长度

struct ring_sig_Key
{
    vector<string> publickey;
    vector<string> privatekey;
};

ring_sig_Key ring_generate()
{
    OpenSSL_add_all_algorithms();
    vector<string> pubkey;
    vector<string> prikey;
    pubkey.resize(station_num);
    prikey.resize(station_num);
    for (int i = 0; i < station_num; i++)
    {
        generateRSAKey(pubkey[i], prikey[i]);
    }
    return ring_sig_Key{ pubkey, prikey };
}

void own_sha256(const std::string& srcStr, std::string& encodedHexStr)
{

    unsigned char mdStr[33] = { 0 };
    SHA256((const unsigned char*)srcStr.c_str(), srcStr.length(), mdStr); // 调用sha256哈希                     // 哈希后的字符串
    char buf[65] = { 0 };
    char tmp[3] = { 0 };
    for (int i = 0; i < 32; i++) // 哈希后的十六进制串 32字节
    {
        sprintf(tmp, "%02x", mdStr[i]);
        strcat(buf, tmp);
    }
    buf[32] = '\0'; // 后面都是0，从32字节截断
    encodedHexStr = std::string(buf);
}

// 生成长度为 k 个字符的非确定性随机数，返回bit字节流
string randlen(uint32_t k)
{

    // 使用随机设备作为种子
    random_device rd;
    // 使用 Mersenne Twister 引擎
    mt19937 gen(rd());
    // 生成一个范围在 0 到 255（包括）的随机整数
    uniform_int_distribution<> dis(0, 255);
    uint32_t r;
    string ss(k, 0x00);
    for (uint32_t i = 0; i < k; i++)
    {
        r = (uint32_t)dis(gen) % 256;
        ss[i] = r;
    }
    return ss;
}

string BIG_XOR(string a, string b)
{
    size_t a_length = a.length();
    size_t b_length = b.length();
    size_t length = a_length >= b_length ? a_length : b_length;
    string ret;
    if (a_length >= b_length)
        ret = a;
    else
        ret = b;
    for (int i = a_length - 1, j = b_length - 1; i >= 0 && j >= 0; i--, j--)
    {
        ret[i >= j ? i : j] = ((unsigned char)a[i] ^ (unsigned char)b[j]);
    }
    return ret;
}

void __ring_sig(string& mes, string Xstr[station_num],
    string& strv, vector<string>& pubkey,
    string& prikey, size_t Iam)
{
    //******************************
    // 生成k
    string hash_input = mes;
    string strk;
    own_sha256(hash_input, strk);
    //******************************
    // 生成v
    strv = randlen(rand_len / 4);
    //******************************
    // 随机生成X集合
    for (size_t i = 0; i < station_num; i++)
    {
        if (i != Iam)
        {
            Xstr[i] = randlen(rand_len / 4);
        }
    }
    //******************************
    // 根据X生成Y集合
    string Ystr[station_num];
    for (size_t i = 0; i < station_num; i++)
    {
        if (i != Iam)
        {
            Ystr[i] = rsa_pub_encrypt(Xstr[i], pubkey[i]);
        }
    }
    //******************************
    // 组合函数C
    string fin = BIG_XOR(strk, strv);
    for (int i = 0; i < station_num; i++)
    {
        if (i != Iam)
            fin = BIG_XOR(Ystr[i], fin);
    }
    Ystr[Iam] = fin;
    Xstr[Iam] = rsa_pri_decrypt(fin, prikey);
}


// 签名函数
void ring_sig(string mes, string Xstr[station_num],
    string& strv, vector<string>& pubkey,
    string& prikey, size_t Iam)
{
    while (1)
    {
        __ring_sig(mes, Xstr, strv, pubkey, prikey, Iam);
        if (Xstr[Iam].length() != 0)
            break;
    }
}


// 验签函数
bool verify_sig(string mes, string Xstr[station_num],
    string strv, vector<string>& pubkey)
{
    //******************************
    // 生成k
    BIGNUM* k = BN_new();
    string hash_input = mes;
    string strk;
    own_sha256(hash_input, strk);
    BN_free(k);
    //******************************
    // 根据X生成Y集合
    string Ystr[station_num];
    for (size_t i = 0; i < station_num; i++)
    {
        Ystr[i] = rsa_pub_encrypt(Xstr[i], pubkey[i]);
    }
    //******************************
    string fin = BIG_XOR(strk, Ystr[0]);
    for (int i = 1; i < station_num; i++)
    {
        fin = BIG_XOR(Ystr[i], fin);
    }
    return fin.compare(strv) == 0;
}

#endif