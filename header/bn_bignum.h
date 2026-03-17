
#define _OWN_BIGNUM_
#ifdef _OWN_BIGNUM_
#include <openssl/bn.h>
#include <iostream>
#include <string>

class bignum
{
public:
    bignum() : value(BN_new())
    {
        BN_hex2bn(&value, "0");
    };
    bignum(const std::string& str) : value(BN_new())
    {
        BN_hex2bn(&value, str.c_str());
    }
    bignum(const char* str) : value(BN_new())
    {
        BN_hex2bn(&value, str);
    }
    std::string bn2hex() 
    {
        return BN_bn2hex(value);
    }
    bignum& operator=(const bignum& p)
    {
        if (value)
            BN_free(value);
        value = BN_new();
        BN_hex2bn(&value, BN_bn2hex(p.value));
        return *this;
    }

    int compare(const bignum& p)
    {
        return BN_cmp(value, p.value);
    }
    bool operator>(const bignum& p)
    {
        return BN_cmp(value, p.value) > 0;
    }
    bool operator<(const bignum& p)
    {
        return BN_cmp(value, p.value) < 0;
    }
    bool operator==(const bignum& p)
    {
        return BN_cmp(value, p.value) == 0;
    }
    // 取相反数
    bignum operator-()
    {
        bignum ret;
        ret = *this;
        if (BN_is_negative(value) == 1)
            BN_set_negative(ret.value, 0);
        else
            BN_set_negative(ret.value, 1);
        return ret;
    }
    // 输出 *this (mod N)
    bignum mod(const bignum& N)
    {
        bignum ret;
        BN_mod(ret.value, value, N.value, ctx);
        return ret;
    }
    static void end()
    {
        if (bignum::ctx)
            BN_CTX_free(bignum::ctx);
    }
    // 素数判定
    bool is_prime()
    {
        return BN_check_prime(value, bignum::ctx, NULL);
    }
    ~bignum()
    {
        BN_free(value);
    }

public:
    BIGNUM* value;
    static bignum_ctx* ctx;
};

bignum_ctx* bignum::ctx = BN_CTX_new();

// 直接加
bignum operator + (const bignum& p, const bignum& q)
{
    bignum ret;
    BN_add(ret.value, p.value, q.value);
    return ret;
}

// 模加
bignum mod_add(const bignum& p, const bignum& q, const bignum& n)
{
    bignum ret;
    BN_mod_add(ret.value, p.value, q.value, n.value, bignum::ctx);
    return ret;
}

// 直接减
bignum operator-(const bignum& p, const bignum& q)
{
    bignum ret;
    BN_sub(ret.value, p.value, q.value);
    return ret;
}

// 模减
bignum mod_sub(const bignum& p, const bignum& q, const bignum& n)
{
    bignum ret;
    BN_mod_sub(ret.value, p.value, q.value, n.value, bignum::ctx);
    return ret;
}

// 直接乘
bignum operator*(const bignum& p, const bignum& q)
{
    bignum ret;
    BN_mul(ret.value, p.value, q.value, bignum::ctx);
    return ret;
}

// 模乘
bignum mod_mul(const bignum& p, const bignum& q, const bignum& n)
{
    bignum ret;
    BN_mod_mul(ret.value, p.value, q.value, n.value, bignum::ctx);
    return ret;
}

// P整除Q
bignum operator/(const bignum& p, const bignum& q)
{
    bignum ret;
    bignum temp;
    BN_div(ret.value, temp.value, p.value, q.value, bignum::ctx);
    return ret;
}

// 幂运算
bignum operator^(const bignum& p, const bignum& q)
{
    bignum ret;
    BN_exp(ret.value, p.value, q.value, bignum::ctx);
    return ret;
}

// 模幂运算
bignum mod_exp(const bignum& p, const bignum& q, const bignum& n)
{
    bignum ret;
    BN_mod_exp(ret.value, p.value, q.value, n.value, bignum::ctx);
    return ret;
}

// 打印输出
std::ostream& operator<<(std::ostream& out, const bignum& it)
{
    out << "0x" << (BN_bn2hex(it.value));
    return out;
}

// 最大公因数
bignum gcd(const bignum& p, const bignum& q)
{
    bignum ret;
    BN_gcd(ret.value, p.value, q.value, bignum::ctx);
    return ret;
}

// 最小公倍数
bignum lcm(const bignum& p, const bignum& q)
{
    bignum ret;
    bignum temp = gcd(p, q);
    return (p * q) / temp;
}

#endif