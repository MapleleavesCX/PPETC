#pragma once
#include<iostream>
#include<string>
#include<vector>

#include"tick.h"

using namespace std;

// S盒
uint8_t Sbox[256] = {
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};


// 固定参数
uint32_t CK[32] = {
0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };

// 系统参数
uint32_t FK[4] = {
	0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC
};

//合成置换T： T(·) = L(t(·))

// L：
uint32_t Lt(uint32_t B) {

    // 循环移位 <<< 2、 10、 18、 24 位
    return B ^ ((B << 2) + (B >> 30)) 
        ^ ((B << 10) + (B >> 22)) 
        ^ ((B << 18) + (B >> 14)) 
        ^ ((B << 24) + (B >> 8));
}

// T:
uint32_t Tr(uint32_t IN) {
    // 先将输入的32-bit数拆分为4个8-bit数
	uint8_t a0 = IN >> 24;
	uint8_t a1 = (IN >> 16) % 256;
	uint8_t a2 = (IN >> 8) % 256;
	uint8_t a3 = IN % 256;
    // 分别经过S盒
    uint8_t b0 = Sbox[a0];
    uint8_t b1 = Sbox[a1];
    uint8_t b2 = Sbox[a2];
    uint8_t b3 = Sbox[a3];
    
    // 移位 重新回到一个完整的32-bit数的状态
    uint32_t B = (b0 << 24) + (b1 << 16) + (b2 << 8) + b3;
	return Lt(B);
}

// L'，用于密钥扩展
uint32_t _Lt(uint32_t B) {
    
    // 循环移位 <<< 0、13、23位后异或
    return B ^ ((B << 13) + (B >> 19)) ^ ((B << 23) + (B >> 9));
}

// T'，用于密钥扩展
uint32_t _Tr(uint32_t IN) {
    // 先将输入的32-bit数拆分为4个8-bit数
	uint8_t a0 = IN >> 24;
	uint8_t a1 = (IN >> 16) % 256;
	uint8_t a2 = (IN >> 8) % 256;
	uint8_t a3 = IN % 256;
    // 分别经过S盒
    uint8_t b0 = Sbox[a0];
    uint8_t b1 = Sbox[a1];
    uint8_t b2 = Sbox[a2];
    uint8_t b3 = Sbox[a3];
    // 移位 重新回到一个完整的32-bit数的状态 
    uint32_t B = (b0 << 24) + (b1 << 16) + (b2 << 8) + b3;
	return _Lt(B);
}



//密钥扩展算法
vector<uint32_t> sm4_get_Key(vector<uint32_t>& MK) {
	vector<uint32_t> K(36, 0x00);
	vector<uint32_t> rk(32, 0x00);

	uint8_t i;
	for (i = 0; i < 4; i++) {
		K[i] = MK[i] ^ FK[i]; // 初始生成 K0,K1,K2,K3
	}
	for (i = 0; i < 32; i++) { // 根据 K0,K1,K2,K3 生成后续 rk[i]
		K[i + 4] = K[i] ^ _Tr(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
		rk[i] = K[i + 4];
	}
	return rk;
}


// 字符转换：输入16字节字符串，输出4个32bit的无符号整型
vector<uint32_t> str2uint_128bit(string M16) {

	vector<uint32_t> out(4, 0x00);

	if (M16.size() != 16) {
		printf("str2uint_128bit error!\n");
		return out;
	}
	else {
		out[0] = 
			(((uint32_t)M16[0] % 256) << 24) 
			+ (((uint32_t)M16[1] % 256) << 16) 
			+ (((uint32_t)M16[2] % 256) << 8) 
			+ ((uint32_t)M16[3] % 256);
		out[1] =
			(((uint32_t)M16[4] % 256) << 24)
			+ (((uint32_t)M16[5] % 256) << 16)
			+ (((uint32_t)M16[6] % 256) << 8)
			+ ((uint32_t)M16[7] % 256);
		out[2] =
			(((uint32_t)M16[8] % 256) << 24)
			+ (((uint32_t)M16[9] % 256) << 16)
			+ (((uint32_t)M16[10] % 256) << 8)
			+ ((uint32_t)M16[11] % 256);
		out[3] =
			(((uint32_t)M16[12] % 256) << 24)
			+ (((uint32_t)M16[13] % 256) << 16)
			+ (((uint32_t)M16[14] % 256) << 8)
			+ ((uint32_t)M16[15] % 256);
		return out;
	}
}

// 类型转换：输入4长的32bit无符号整型，输出16字节字符串
string uint2str_16byte(vector<uint32_t>& M128) {

	string out(16, 0x00);

	if (M128.size() != 4) {
		printf("uint2str_16byte error!\n");
		return out;
	}
	else {
		for (uint8_t i = 0; i < 4; i++) {
			out[0 + 4 * i] = M128[i] >> 24;
			out[1 + 4 * i] = (M128[i] >> 16) % 256;
			out[2 + 4 * i] = (M128[i] >> 8) % 256;
			out[3 + 4 * i] = M128[i] % 256;
		}
		return out;
	}
}


void F(vector<uint32_t>& X, vector<uint32_t> rk) {
    for (uint8_t i = 0; i < 32; i++) {
        // 轮函数 F
        X[i + 4] = X[i] ^ Tr(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);

        //printf("rk[%02d]=%08X    X[%02d]=%08X\n", i, rk[i], i, X[i]);
    }
}


// sm4的加解密函数与模式选择
#define sm4_enc 1
#define sm4_dec 2

bool sm4(string& OUT16, string IN16, string KEY16, uint32_t work_mode) {
    
    vector<uint32_t> in4 = str2uint_128bit(IN16);
    vector<uint32_t> key4 = str2uint_128bit(KEY16);
    vector<uint32_t> rk = sm4_get_Key(key4);

    vector<uint32_t> X(36, 0x00);
    vector<uint32_t> Y(4, 0x00);

    X[0] = in4[0];
    X[1] = in4[1];
    X[2] = in4[2];
    X[3] = in4[3];

    if (work_mode == sm4_enc) { // 加密模式，密钥正序
        F(X, rk);
    }
    else if (work_mode == sm4_dec) { // 解密模式，密钥逆序
        for (uint8_t i = 0, j = 31; i < 32; i++, j--) {
            // 轮函数 F
            X[i + 4] = X[i] ^ Tr(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[j]);
        }
    }
    else {
        printf("the wrong working mode!\n");
        return false;
    }

    Y[0] = X[35];
    Y[1] = X[34];
    Y[2] = X[33];
    Y[3] = X[32];
    OUT16 = uint2str_16byte(Y);

    return true;
}



////////////////////////工作模式////////////////////////////

#define ECB_enc 1
#define ECB_dec 2

#define CBC_enc 3
#define CBC_dec 4

#define CTR_enc 5
#define CTR_dec 6

//嵌套了工作模式的sm4算法

bool sm4work(uint8_t work_mode, string& output, string input, string Key, string IV="1234567890ABCDEF") {

    if (Key.size() != 16)
    {
        printf("sm4work Error！Key length does not match 128bit.\n");
        return false;
    }

    output = "";
    size_t len = input.size();
    string iv = IV;
    string key = Key;


    if (work_mode == ECB_enc) {
        if (len % 16 != 0) {
            printf("sm4work ECB Error！The length of the plaintext to be encrypted does not meet a multiple of 16 bytes.\n");
            return false;
        }
        else {
            string P(16, 0x00), C(16, 0x00);
            size_t num = len / 16;
            for (uint32_t i = 0; i < num; i++) {
                P = input.substr(i * 16, 16);
                if (sm4(C, P, key, sm4_enc))
                {
                    output += C;
                }
                else
                {
                    printf("sm4work ECB Error！Encryption failed for segment %d.\n", i + 1);
                    return false;
                }
            }
            return true;
        }
    }
    else if (work_mode == ECB_dec) {
        if (len % 16 != 0) {
            printf("sm4work ECB Error！The length of the plaintext to be encrypted does not meet a multiple of 16 bytes.\n");
            return false;
        }
        else {
            string P(16, 0x00), C(16, 0x00);
            size_t num = len / 16;
            for (uint32_t i = 0; i < num; i++) {
                C = input.substr(i * 16, 16);
                if (sm4(C, P, key, sm4_dec))
                {
                    output += P;
                }
                else
                {
                    printf("sm4work ECB Error！Encryption failed for segment %d.\n", i + 1);
                    return false;
                }
            }
            return true;
        }
    }
    else if (work_mode == CBC_enc) {
        string P(16, 0x00), C(16, 0x00), temp(16, 0x00), enc_in(16, 0x00);

        // 初始化iv
        for (size_t t = 0; t < 16; t++) {
            temp[t] = iv[t];
        }

        size_t num = len / 16;

        uint32_t i = 0;
        while (i < num) {

            P = input.substr(i * 16, 16);

            for (size_t t = 0; t < 16; t++) {
                enc_in[t] = temp[t] ^ P[t];
            }

            if (sm4(C, P, key, sm4_enc))
            {
                output += C;
                temp = C;
                i++;
            }
            else
            {
                printf("sm4work CBC Error！Encryption failed for segment %d.\n", i + 1);
                return false;
            }
        }

        //处理长度不为16的最后一段的情况
        size_t last = len % 16;
        if (last == 0) {
            return true;
        }
        else {

            P = input.substr(len - last, last);
            P += "0000000000000000";

            for (size_t t = 0; t < 16; t++) {
                enc_in[t] = temp[t] ^ P[t];
            }

            if (sm4(C, P, key, sm4_enc))
            {
                output += C;
                temp = C;
            }
            else
            {
                printf("sm4work CBC Error！Encryption failed for segment %d.\n", i + 1);
                return false;
            }
        }

        return true;
    }
    else if (work_mode == CBC_dec) {
        string P(16, 0x00), C(16, 0x00), temp(16, 0x00), dec_out(16, 0x00);

        // 初始化iv
        for (size_t t = 0; t < 16; t++) {
            temp[t] = iv[t];
        }

        size_t num = len / 16;

        uint32_t i = 0;
        while (i < num) {

            C = input.substr(i * 16, 16);

            if (sm4(C, P, key, sm4_dec))
            {
                for (size_t t = 0; t < 16; t++) {
                    P[t] = temp[t] ^ dec_out[t];
                }
                output += P;
                temp = C;
                i++;
            }
            else
            {
                printf("sm4work CBC Error！Encryption failed for segment %d.\n", i + 1);
                return false;
            }
        }

        //处理长度不为16的最后一段的情况
        size_t last = len % 16;
        if (last == 0) {
            return true;
        }
        else {

            C = input.substr(len - last, last);
            C += "0000000000000000";

            if (sm4(C, P, key, sm4_dec))
            {
                for (size_t t = 0; t < 16; t++) {
                    P[t] = temp[t] ^ dec_out[t];
                }
                output += P;
                temp = C;
                i++;
            }
            else
            {
                printf("sm4work CBC Error！Encryption failed for segment %d.\n", i + 1);
                return false;
            }
        }
        return true;
    }
    else if (work_mode == CTR_enc) {

        tick T;

        string C(16, 0x00), P(16, 0x00), enc_out(16, 0x00), temp = "";

        size_t num;
        size_t last = len % 16;
        if (last == 0) {
            num = len / 16;
        }
        else {
            num = len / 16 + 1;
        }

        uint32_t i = 0;
        size_t L = len;

        while (T.add1()) {
            if (!sm4(enc_out, T.counter, key, sm4_enc))
            {
                printf("sm4work CTR Error！Encryption failed for segment %d.\n", i + 1);
                return false;
            }
            size_t getlen = L > 16 ? 16 : L;
            P = input.substr(i * 16, getlen);
            L -= 16;

            for (size_t t = 0; t < getlen; t++) {
                C[t] = P[t] ^ enc_out[t];
            }
            temp += C;

            i++;
            if (i == num)
            {
                output = temp.substr(0, len);
                return true;
            }
        }
        printf("sm4work CTR Error！Exceeding the maximum encryptable length.\n");
        return false;
    }
    else if (work_mode == CTR_dec) {

        tick T;
        string C(16, 0x00), P(16, 0x00), enc_out(16, 0x00), temp = "";

        size_t num;
        size_t last = len % 16;
        if (last == 0) {
            num = len / 16;
        }
        else {
            num = len / 16 + 1;
        }

        uint32_t i = 0;
        size_t L = len;

        while (T.add1()) {
            if (!sm4(enc_out, T.counter, key, sm4_enc))
            {
                printf("sm4work CTR Error！Encryption failed for segment %d.\n", i + 1);
                return false;
            }
            size_t getlen = L > 16 ? 16 : L;
            C = input.substr(i * 16, getlen);
            L -= 16;

            for (size_t t = 0; t < getlen; t++) {
                P[t] = C[t] ^ enc_out[t];
            }
            temp += P;

            i++;
            if (i == num)
            {
                output = temp.substr(0, len);
                return true;
            }
        }
        printf("sm4work CTR Error！Exceeding the maximum encryptable length.\n");
        return false;
    }
    else {
        printf("sm4work Error！Unsupported working mode.\n");
        return false;
    }
}
