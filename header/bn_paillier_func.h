#pragma once

#include <iostream>
#include <iomanip>
#include <sstream>
#include<vector>
#include <chrono>
#include <string>
#include<random>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

#include"tool_func.h"
using namespace std;

////////////////////////////////////////////////

struct PaillierKey {
    vector<string> privatekey;
    vector<string> publickey;
};


string _sm3(const string& input) {
    EVP_MD_CTX* mdctx;
    unsigned char hash[32];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << hex << uppercase << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// 计算最小公倍数
BIGNUM* BN_lcm(BIGNUM* a, BIGNUM* b) {

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* result = BN_new();
    BIGNUM* ab = BN_new();

    // 计算最大公约数
    BIGNUM* gcd = BN_new();
    BN_gcd(gcd, a, b, ctx);
    // 计算最小公倍数
    BN_mul(ab, a, b, ctx);
    BN_div(result, NULL, ab, gcd, ctx);

    // 释放资源
    BN_free(gcd);
    BN_free(ab);
    BN_CTX_free(ctx);
    return result;
}

bool get_prime(string& prime, string& randseed, string fixedseed, uint32_t bit_of_prime) {

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* P = BN_new();

    bool loop = true;
    if (randseed != "")
        loop = false;

    int isprime = 0;
    while (true) {
        if (loop) {
            randseed = randstr('A', 'G', 32);
        }

        string a = randseed + fixedseed;
        prime = "";
        for (uint32_t l = 0; l < (bit_of_prime / 256); l++) {
            string b = _sm3(a);
            prime += b;
            a = b;
        }

        BN_hex2bn(&P, prime.c_str());
        isprime = BN_check_prime(P, ctx, NULL);

        if (!loop || isprime == 1)
        {
            BIGNUM* REM = BN_new();
            BIGNUM* four = BN_new();
            BN_set_word(four, 4);
            BIGNUM* three = BN_new();
            BN_set_word(three, 3);
            BN_div(NULL, REM, P, four, ctx);
            string ttt = BN_bn2hex(REM);

            if (BN_cmp(REM, three) == 0) {
                break;
            }
        }
    }
    BN_free(P);
    BN_CTX_free(ctx);
    if (isprime == 1) {
        return true;
    }
    else {
        cout << "***Func get_prime Error:The number which used the input randnumber '" << randseed << "' to generate isn't prime!\n";
        return false;
    }
}


PaillierKey Paillier_key_generate(string& x1,
    string& x2, string uid, string when) {

    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* P = BN_new();
    BIGNUM* Q = BN_new();
    BIGNUM* P_1 = BN_new();
    BIGNUM* Q_1 = BN_new();
    BIGNUM* P_1_Q_1 = BN_new();
    BIGNUM* N = BN_new();
    BIGNUM* N2 = BN_new();

    BIGNUM* H = BN_new();
    BIGNUM* Hs = BN_new();
    BIGNUM* X = BN_new();
    BIGNUM* X2 = BN_new();
    BIGNUM* LA = BN_new();

    BIGNUM* G = BN_new();
    BIGNUM* Y = BN_new();
    BIGNUM* Y_1 = BN_new();
    BIGNUM* L = BN_new();

    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    BIGNUM* two = BN_new();
    BN_set_word(two, 2);


    BIGNUM* MU = BN_new();
    string p_str, q_str, fixed = uid + when;
    
    BIGNUM* OUT = BN_new();
    while (true) {

        x1 = "", x2 = "";
        get_prime(p_str, x1, fixed, 1024);
        get_prime(q_str, x2, fixed, 1024);

        // 转换外界输入素数p,q
        BN_hex2bn(&P, p_str.c_str());
        BN_hex2bn(&Q, q_str.c_str());

        // P - 1
        BN_sub(P_1, P, one);
        // Q - 1
        BN_sub(Q_1, Q, one);

        BN_gcd(OUT, P_1, Q_1, ctx);
        string out = BN_bn2hex(OUT);
        if (BN_cmp(OUT, two) == 0)
        {
            break;
        }
    }


    // N = P * Q
    BN_mul(N, P, Q, ctx);
    // N^2
    BN_mul(N2, N, N, ctx);

    // 随机一个数 X in [1, N - 1]
    BN_rand_range(X, N);
    if (BN_is_zero(X))
        BN_add(X, X, BN_value_one());

    // X^2
    BN_mul(X2, X, X, ctx);
    // H = -X^2 mod N^2
    BN_sub(H, N2, X2);
    // Hs = H^N mod N^2
    BN_mod_exp(Hs, H, N, N2, ctx);

    
    // (P - 1)*(Q - 1)
    BN_mul(P_1_Q_1, P_1, Q_1, ctx);
    // λ = (P - 1)*(Q - 1) / 2
    BN_div(LA, NULL, P_1_Q_1, two, ctx);

    // G = N + 1
    BN_add(G, N, one);
    // Y = G^λ mod N^2
    BN_mod_exp(Y, G, LA, N2, ctx);
    // Y - 1
    BN_sub(Y_1, Y, one);

    BIGNUM* rem = BN_new();
    // L = (Y - 1) / N
    BN_div(L, rem, Y_1, N, ctx);
    //  μ = inv(L, N)
    BN_mod_inverse(MU, L, N, ctx);

    PaillierKey HKEY;
    //转换类型，返回公钥(n,g), 私钥 (n,λ,μ)
    string n, hs, lamuda, mu;
    n = BN_bn2hex(N);
    hs = BN_bn2hex(Hs);
    lamuda = BN_bn2hex(LA);
    mu = BN_bn2hex(MU);
    HKEY.publickey.push_back(fill0(hex2bit(n), 256));
    HKEY.publickey.push_back(fill0(hex2bit(hs),512));
    HKEY.privatekey.push_back(hex2bit(n));
    HKEY.privatekey.push_back(hex2bit(lamuda));
    HKEY.privatekey.push_back(hex2bit(mu));

    BN_free(one);
    BN_free(two);
    BN_free(P);
    BN_free(Q);
    BN_free(P_1);
    BN_free(Q_1);
    BN_free(P_1_Q_1);
    BN_free(N);
    BN_free(N2);
    BN_free(H);
    BN_free(Hs);
    BN_free(X);
    BN_free(X2);
    BN_free(G);
    BN_free(Y);
    BN_free(Y_1);
    BN_free(L);
    BN_free(LA);
    BN_free(MU);
    BN_CTX_free(ctx);

    return HKEY;
}

bool Enc_Paillier(string m,
    vector<string> publickey, string& output) {

    // 转换外界输入公钥(n,g)
    string n_str = bit2hex(publickey[0]);
    string hs_str = bit2hex(publickey[1]);
    string m_str = bit2hex(m);

    if (m_str == "" || n_str == "" || hs_str == "")
        return false;

    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* N = BN_new();
    BIGNUM* Hs = BN_new();

    BN_hex2bn(&N, n_str.c_str());
    BN_hex2bn(&Hs, hs_str.c_str());

    BIGNUM* M = BN_new();
    BIGNUM* C = BN_new();

    //转换明文m
    BN_hex2bn(&M, m_str.c_str());
    // N^2
    BIGNUM* N2 = BN_new();
    BN_mul(N2, N, N, ctx);
    // (1 + M*N)
    BIGNUM* MN = BN_new();
    BIGNUM* one_MN = BN_new();
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);
    BN_mul(MN, M, N, ctx);
    BN_add(one_MN, MN, one);

    // 随机一个数 A in [1, |N|/2]
    BIGNUM* A = BN_new();
    
    uint64_t len_of_N = n_str.length();
    string half_str(len_of_N / 2 + 1, '0');
    half_str[0] = '1';
    BIGNUM* HALF = BN_new();
    BN_hex2bn(&HALF, half_str.c_str());
    BN_rand_range(A, HALF);
    if (BN_is_zero(A))
        BN_add(A, A, BN_value_one());
    BN_free(HALF);

    BIGNUM* Hs_up_A = BN_new();

    BN_mod_exp(Hs_up_A, Hs, A, N2, ctx);


    BN_mod_mul(C, one_MN, Hs_up_A, N2, ctx);

    // 转换密文字符串
    output = hex2bit(BN_bn2hex(C));


    BN_free(N);
    BN_free(N2);
    BN_free(Hs);
    BN_free(MN);
    BN_free(one_MN);
    BN_free(one);
    BN_free(A);
    BN_free(Hs_up_A);
    BN_free(M);
    BN_free(C);
    BN_CTX_free(ctx);
    return true;
}


bool Dec_Paillier(string c,
    vector<string> privatekey, string& output) {
    
    // 转换外界输入私钥 (n,λ,μ)
    string n_str = bit2hex(privatekey[0]);
    string lamuda_str = bit2hex(privatekey[1]);
    string mu_str = bit2hex(privatekey[2]);
    string c_str = bit2hex(c);
    if (c_str == "" || n_str == "" || lamuda_str == "" || mu_str == "")
        return false;

    BN_CTX* ctx = BN_CTX_new();
    BN_MONT_CTX* mont_ctx = BN_MONT_CTX_new();

    BIGNUM* N = BN_new();
    BIGNUM* LA = BN_new();
    BIGNUM* MU = BN_new();


    BN_hex2bn(&N, n_str.c_str());
    BN_hex2bn(&LA, lamuda_str.c_str());
    BN_hex2bn(&MU, mu_str.c_str());
    

    BIGNUM* N2 = BN_new();
    BIGNUM* X = BN_new();
    BIGNUM* X_1 = BN_new();
    BIGNUM* L = BN_new();
    BIGNUM* one = BN_new();
    BN_set_word(one, 1);

    BIGNUM* M = BN_new();
    BIGNUM* C = BN_new();

    //转换密文c
    BN_hex2bn(&C, c_str.c_str());
    // N^2
    BN_mul(N2, N, N, ctx);
    // X = C^λ mod N^2
    BN_mod_exp(X, C, LA, N2, ctx);
    // X - 1
    BN_sub(X_1, X, one);
    // L = (X - 1) / N
    BN_div(L, NULL, X_1, N, ctx);
    // M = L * μ mod N
    BN_mod_mul(M, L, MU, N, ctx);

    // 转换明文字符串
    output = hex2bit(BN_bn2hex(M));


    BN_free(N);
    BN_free(N2);
    BN_free(LA);
    BN_free(MU);
    BN_free(M);
    BN_free(C);
    BN_free(X);
    BN_free(X_1);
    BN_free(L);
    BN_free(one);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont_ctx);

    return true;
}
