#pragma once

#include <iostream>
#include <iomanip>
#include <sstream>
#include<vector>
#include <chrono>
#include <string>
#include<random>

using namespace std;

//计时函数（被计时的函数本身无法返回值）,返回计算时间，单位：微秒
template<typename Func, typename... Args>
uint64_t timing(Func func, Args&&... args)
{
    auto start = chrono::system_clock::now();
    func(args...);
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    uint64_t tt = duration.count();
    cout << "执行用时：" << (double)((double)tt / 1000) << " ms\n";
    return tt;
}

//字符串类型整数字节流转换为字符串表示的十六进制数
string bit2hex(string input) {
    if (input == "")
        return "";

    stringstream ss;
    uint8_t t;
    size_t len = input.length();
    for (size_t i = 0; i < len; i++) {
        t = input[i];
        ss << hex << uppercase << setw(2) << setfill('0') << (int)t;
    }

    return ss.str();
}

//将字符串表示的十六进制数转换为整数字节流
string hex2bit(string input) {

    if (input == "")
        return "";

    size_t L = input.length();
    string instr;
    if (L % 2 != 0) {
        //cout << "Error! Character length is not a multiple of '2'\n";
        instr = "0" + input;
        L++;
    }
    else {
        instr = input;
    }
    string output = "";
    uint16_t x = 0, t = 0;
    for (size_t i = 0, j = 0; i < L; i++) {
        if (instr[i] >= '0' && instr[i] <= '9')
        {
            x = instr[i] - '0';
        }
        else if (instr[i] >= 'a' && instr[i] <= 'f')
        {
            x = instr[i] - 'a' + 10;
        }
        else if (instr[i] >= 'A' && instr[i] <= 'F')
        {
            x = instr[i] - 'A' + 10;
        }
        else
        {
            cout << "Error! Single character representation exceeds the hexadecimal range.\n";
            return "";
        }
        if (i % 2 == 0) {
            t += x * 16;
        }
        else {
            t += x;
            output.push_back(t);
            t = 0;
        }
    }
    return output;
}

// 随机生成长度为len的字符串，其中每个字符的范围是[low, up)
string randstr(char low, char up, size_t len) {

    // 使用随机设备作为种子
    random_device rd;
    // 使用 Mersenne Twister 引擎
    mt19937 gen(rd());
    // 生成一个范围在 [low, up) 的随机整数
    uniform_int_distribution<> dis((uint8_t)low, (uint8_t)up);

    uint32_t r;
    string ss(len, 0x00);
    for (uint32_t i = 0; i < len; i++) {
        r = (uint32_t)dis(gen) % 256;
        ss[i] = r;
    }
    return ss;
}

string fill0(string input_str, size_t fill_len) {
    size_t in_len = input_str.length();
    if (fill_len == in_len)
        return input_str;
    else if(fill_len > in_len)
    {
        string zero(fill_len - in_len, 0);
        return zero + input_str;
    }
    else{
        cout << " *fill0 错误！超长度\n";
        return "";
    }
}