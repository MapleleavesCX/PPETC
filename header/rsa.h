#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/des.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
using namespace std;

// ---- rsa非对称加解密 ---- //
#define KEY_LENGTH 1024 // 密钥长度

// 函数方法生成密钥对
void generateRSAKey(std::string& pubKey, std::string& priKey)
{
    // 公私密钥对
    size_t pri_len;
    size_t pub_len;
    char* pri_key = NULL;
    char* pub_key = NULL;

    // 生成密钥对
    RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    // 存储密钥对
    pubKey = pub_key;
    priKey = pri_key;

    // 内存释放
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}
void generateRSAKey(std::string Key[2])
{
    // 公私密钥对
    size_t pri_len;
    size_t pub_len;
    char* pri_key = NULL;
    char* pub_key = NULL;

    // 生成密钥对
    RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    // 存储密钥对
    Key[0] = pub_key;
    Key[1] = pri_key;

    // 内存释放
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

// 公钥加密
std::string rsa_pub_encrypt(const std::string& clearText, const std::string& pubKey)
{
    string strRet;
    RSA* rsa = NULL;
    BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
    RSA* pRSAPublicKey = RSA_new();
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    // 加密函数
    int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText,
        rsa, RSA_NO_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, ret);
    // 释放内存
    free(encryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}

// 私钥解密
std::string rsa_pri_decrypt(const std::string& cipherText, const std::string& priKey)
{
    std::string strRet;
    RSA* rsa = RSA_new();
    BIO* keybio;
    keybio = BIO_new_mem_buf((unsigned char*)priKey.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

    int len = RSA_size(rsa);
    char* decryptedText = (char*)malloc(len + 1);
    memset(decryptedText, 0, len + 1);

    // 解密函数
    int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText,
        rsa, RSA_NO_PADDING);
    if (ret >= 0)
        strRet = std::string(decryptedText, ret);

    // 释放内存
    free(decryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}

string _SHA256(const std::string& srcStr)
{
    unsigned char mdStr[33] = { 0 };
    SHA256((const unsigned char*)srcStr.c_str(), srcStr.length(), mdStr); // 调用sha256哈希                     // 哈希后的字符串
    mdStr[32] = '\0';
    return std::string((char*)mdStr);
}

// ************************************************************

// RSA签名
string RSA_sig(string input, string prikey)
{
    string ret = _SHA256(input);
    string temp = ret;
    for (int i = 0; i < 3; i++)
    {
        temp = _SHA256(temp);
        ret += temp;
    }
    return rsa_pri_decrypt(ret, prikey);
}

// RSA验签
bool ver_RSA_sig(string input, string sig, string pubkey, string prikey)
{
    string ret = _SHA256(input);
    string temp = ret;
    for (int i = 0; i < 3; i++)
    {
        temp = _SHA256(temp);
        ret += temp;
    }
    string origin = rsa_pub_encrypt(sig, pubkey);
    for (int i = 0; i < origin.length(); i++)
        cout << (int)(unsigned char)origin[i] << " ";
    cout << endl
        << endl;
    string k1 = rsa_pri_decrypt(origin, prikey);
    for (int i = 0; i < ret.length(); i++)
        cout << (int)(unsigned char)ret[i] << " ";
    cout << endl
        << endl;
    return origin.compare(ret) == 0;
}
