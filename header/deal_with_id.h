#ifndef _DEAL_WITH_ID_
#define _DEAL_WITH_ID_

#include <cstdlib>
#include <string>
#include <cstring>
#include <time.h>

#include"allheader.h"
using namespace std;

//string sm3(const string input)

string get_uid()
{
    srand((unsigned)time(NULL));
    string ret;
    for (int i = 0; i < 4; i++)
        ret += to_string(rand());
    return sm3(ret);
}

string get_id(const string& uid)
{
    return sm3(uid);
}

string get_when()
{
    time_t now = time(0);
    char temp_time[8] = { 0,0,0,0,0,0,0,0 };
    tm* ltm = localtime(&now);
    string year = to_string(1900 + ltm->tm_year);
    string month = 1 + ltm->tm_mon > 9 ? to_string(1 + ltm->tm_mon) : string("0") + to_string(1 + ltm->tm_mon);
    string data = ltm->tm_mday > 9 ? to_string(ltm->tm_mday) : string("0") + to_string(ltm->tm_mday);
    return year + month + data;
}

#endif