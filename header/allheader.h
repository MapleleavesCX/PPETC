////////////////////////////////////////////////
#include"tool_func.h"
template<typename Func, typename... Args>
uint64_t timing(Func func, Args&&... args);

string bit2hex(string input);

string hex2bit(string input);

// 随机生成len长字符串，每个字符的范围是[low, up)
string randstr(char low, char up, size_t len);

// 为input_str填充字符'0'至指定长度的字符串
string fill0(string input_str, size_t fill_len);
////////////////////////////////////////////////
#include"bn_paillier_func.h"

BIGNUM* BN_lcm(BIGNUM* a, BIGNUM* b);

// input uid,when;output x1,x2,pk=(n,g),sk=(n,λ,μ)
PaillierKey Paillier_key_generate(string& x1,
    string& x2, string uid, string when);

// input m, pk=(n,g)
bool Enc_Paillier(string m,
    vector<string> publickey, string& output);

// input c, sk=(n,λ,μ)
bool Dec_Paillier(string c,
    vector<string> privatekey, string& output);
////////////////////////////////////////////////
#include"sm4.h"

#define sm4_enc 1
#define sm4_dec 2

bool sm4(string& OUT16, string IN16,
    string KEY16, uint32_t work_mode);

// work_mode
#define ECB_enc 1
#define ECB_dec 2

#define CBC_enc 3
#define CBC_dec 4

#define CTR_enc 5
#define CTR_dec 6

bool sm4work(uint8_t work_mode, string& output, 
    string input, string Key, 
    string IV);
////////////////////////////////////////////////

#include"bn_sm2.h"

void sm2_getKey(string& sk, vector<string>& pk);

void sm2_sign(vector<string>& sign, 
    string& message, string& sk);

bool sm2_verify(string& message, 
    vector<string>& sign, vector<string>& pk);

bool sm2_enc(vector<string>& c1c2c3, 
    string& message, vector<string>& pk);

bool sm2_dec(string& M, string& sk, 
    vector<string>& c1c2c3);

////////////////////////////////////////////////
#include"bn_sm3.h"

string sm3(const string input);

string sm3_mac(string key, string input);

bool sm3_verimac(string key, string message, 
    string mac);

////////////////////////////////////////////////
#include"ring_sig.h"

ring_sig_Key ring_generate();

// 签名函数
void ring_sig(string mes, string Xstr[station_num],
    string& strv, vector<string>& pubkey,
    string& prikey, size_t Iam);

// 验签函数
bool verify_sig(string mes, string Xstr[station_num],
    string strv, vector<string>& pubkey);

////////////////////////////////////////////////
#include"deal_with_id.h"

string get_uid();

string get_id(const string& uid);

string get_when();