#define ETC_OBU
//#define TEST

#ifdef ETC_OBU

#include"C:/Users/-ASUS-/Desktop/ETC/header/allheader.h"
#include"C:/Users/-ASUS-/Desktop/ETC/header/winsock.h"

////////////////////服务端主机的IP地址///////////////////////////
string in_ip = "172.25.141.175";
string out_ip = "172.25.141.175";
const size_t station_number = 256;//要与ring_sign.h里的station_num数值统一
//////////////////////////////////////////////////////////////

////////////////////OBU相关参数/////////////////////////////////
string uid = get_uid();
string ID = get_id(uid);
//////////////////////////////////////////////////////////////



//////////////////////////ETC主体//////////////////////////////
int OBU();

int main() {
    OBU();
}

int OBU() {
    cout << "OBU启动:\n";
    cout << "*生成本次收费路段使用的同态密钥...";

    string when_in = get_when();
    string randp, randq;
    auto start = chrono::system_clock::now();
    PaillierKey hkey = Paillier_key_generate(randp, randq, uid, when_in);
    //cout << "hpk0字节长度：" << hkey.publickey[0].length() << "字节\n";
    //cout << "hpk1字节长度：" << hkey.publickey[1].length() << "字节\n";
    //cout << "hpk[0] = \n" << bit2hex(hkey.publickey[0]) << endl;
    //cout << "hpk[1] = \n" << bit2hex(hkey.publickey[1]) << endl;
    //cout << "hsk0字节长度：" << hkey.privatekey[1].length() << "字节\n";
    //cout << "hsk1字节长度：" << hkey.privatekey[2].length() << "字节\n";

    string in_hpk_rand = hkey.publickey[0] + hkey.publickey[1] + randp + randq;
    cout << "完成!\n";
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    uint64_t tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    /////////////////////////////////////////////////////////////////////
    cout << "***********准备进站***********\n\n";
    cout << "*生成本地临时会话非对称密钥...";
    string sm2_insk;
    vector<string> sm2_inpk;


    start = chrono::system_clock::now();
    sm2_getKey(sm2_insk, sm2_inpk);
    cout << "完成!\n";
    //cout << "sm2:pk:" << sm2_inpk[0].length() << " " << sm2_inpk[1].length() << " sk:" << sm2_insk.length() << endl;
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    ////////////////////////////////进站/////////////////////////////////
    auto startin = chrono::system_clock::now();

    cout << "*准备与收费站 " << in_ip << " 建立通信:\n";
    winsock OBU;
    SOCK INstation;
    if (!OBU.linking_to_server(INstation, in_ip)) {
        return 0;
    }

    //建立安全信道
    cout << "*正在建立安全信道...";

    start = chrono::system_clock::now();
    string inSkey, inIV;
    if (!INstation.client_secure_channel_set(sm2_insk, sm2_inpk[0] + sm2_inpk[1])) {
        cout << "失败！\n";
        return 0;
    }
    cout << "成功！\n";
    cout << ">已发送用对称密码加密的同态公钥相关密文  长度：" << in_hpk_rand.size() << endl;
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    // 发送同态公钥和随机数rand 以及对此的MAC(自动mac与自动认证)
    start = chrono::system_clock::now();
    if (!INstation.secure_sendto(in_hpk_rand)) {
        return 0;
    }

    cout << ">已发送用对称密码加密的同态公钥相关密文  长度：" << in_hpk_rand.size() << endl;
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";

    // 接收服务器返回的消息
    cout << "等待对方发送...\n";
    string HC = INstation.secure_receivefrom(
        512 * (station_number + 2) +
        128 * (station_number + 1) + 64);
    if (HC == "") {
        cout << "接收失败！\n";
        return 0;
    }
    cout << "<来自服务端明文 总长度：" << HC.length() << " 字节\n";


    auto endin = chrono::system_clock::now();
    auto durationin = chrono::duration_cast<chrono::microseconds>(endin - startin);
    uint64_t tin = durationin.count();
    cout << "进站  用时：" << (double)((double)tin / 1000) << " ms\n\n";


    cout << "进站交互结束，可以进入收费路段.\n\n";
    /////////////////////////////////////////////////////////////////////


    cout << "\n\n***********准备出站***********\n\n";

    cout << "*提前生成本地临时会话非对称密钥...";
    string sm2_outsk;
    vector<string> sm2_outpk;
    sm2_getKey(sm2_outsk, sm2_outpk);
    cout << "完成!\n";
    cout << "\n\n";





    ////////////////////////////////出站/////////////////////////////////
    auto startout = chrono::system_clock::now();


    cout << "*准备与收费站 " << out_ip << " 建立通信:\n";
    SOCK OUTstation;
    if (!OBU.linking_to_server(OUTstation, out_ip)) {
        cout << "失败！\n";
        return 0;
    }

    //建立安全信道
    cout << "*正在建立安全信道...";
    if (!OUTstation.client_secure_channel_set(sm2_outsk, sm2_outpk[0] + sm2_outpk[1])) {
        cout << "失败！\n";
        return 0;
    }
    cout << "完成*\n\n";

    // 发送 同态公钥 + 同态密文
    string hc_hpk = hkey.publickey[0] + hkey.publickey[1] + HC;

    cout << "发送同态公钥 + 同态密文\n";



    if (!OUTstation.secure_sendto(hc_hpk)) {
        return 0;
    }
    cout << ">已发送用对称密码加密的同态公钥相关密文  长度：" << hc_hpk.size() << "字节\n";

    /* 接收内容：
    Φ(cost)|| SigCost || Φ(in_id) || Φ(whenin)||
     512      128*(num+1)  512         512
    Φ(out_id) || Φ(whenout) || SignINOUT || randp || randq
     512         512           128*(num+1)   32      32 */
    cout << "<等待接收账单...";
    string bill = OUTstation.secure_receivefrom(
        512 + 128 * (station_number + 1) +
        512 + 512 + 512 + 512 +
        128 * (station_number + 1) + 32 + 32);
    if (bill == "")
    {
        cout << "接收失败！\n";
        return 0;
    }
    cout << "成功！\n";
    cout << "接收账单长度：" << bill.size() << "字节\n";
    //只取Φ(cost)，余下原封不动存为账单
    cout << "正在解密费用...";
    string costC = bill.substr(0, 512), cost;

    if (!Dec_Paillier(costC, hkey.privatekey, cost))
    {
        cout << "失败！\n";
        return 0;
    }
    cout << "成功！*\n";
    cout << "<最终费用：" << bit2hex(cost) << " 元>\n";



    auto endout = chrono::system_clock::now();
    auto durationout = chrono::duration_cast<chrono::microseconds>(endout - startout);
    uint64_t tout = durationout.count();
    cout << "出站  用时：" << (double)((double)tout / 1000) << " ms\n\n";


    return 0;
}




#endif

#ifdef TEST

#define ETC_OBU


#include"C:/Users/-ASUS-/Desktop/ETC/header/allheader.h"

const size_t station_number = 128;
size_t in_id = 3;
////////////////////////////////////////////////////////////////////////////////////////


size_t station_money_lib[station_number];
string get_money(vector<string> cip, string N);


#ifdef ETC_OBU


int main() {

    string x1, x2, when = get_when();
    string uid = "123456";
    //PaillierKey hkey = Paillier_key_generate(x1, x2, uid, when);
    //cout << "sk:\n" << bit2hex(hkey.privatekey[1]) << endl << bit2hex(hkey.privatekey[2]) << endl;
    //cout << "pk:\n" << bit2hex(hkey.publickey[0]) << endl << bit2hex(hkey.publickey[1]) << endl;

    PaillierKey hkey;
    string n = "146A0878EB746B4B497A9269F44771EE30231A03B10EE6340541EBDAADAAEC1801237B706DD34A17DEEB98E64B47B017512433B2BA8749848274DA5E029EEDB69A00BAB3FAD84E582BE321B4CC653ED81CFF61B219DCD6154EA2561FFB676E480DF402845FD808932612919F185A0C38864E6E445248DF103566E58080BA22FA157B09C3971216292DF721EEA03EF53B17AEF963EADDC3B251600B1775DFB62BE4630FC2A639B21CECD963FA329622BC375233BD8D06B771DD3E3F1724DFD762F82D812F7E756EDDCDFF74941566E5119FC06DBCEFB75DFF25BDCF47EB673C39ACE94726268E0EA5638C30939D8AA962DB6A24EA5BDA8E41C92D23E3D2831501";
    string hs = "00CFE8446526B1869F35E1D8BDB1AD547ED21673E2A54A2ED4831EE641EB33CB636B1AEBBC2B04CD65A37445A6766534F8C345D8CEE30FFB499C61603CF7473E53B435130A50ECB282865089B5A6E011E4302BE1CA607DCF6B94C26240C3ADEC081D546F57393BA5A96F547941E6D1B8A0498CD67AB165D5456401BBBBD2D85FF0BA05534CA85534A68B28B30E83434316F33A6C7EB1A5F8B186CC54BCCC1B8DB4081C5C135E7D148C2CC230A1D1C477206976F6472693717FC113C5F6E82E9E6358424B1CADCB0277FB7C0D4C2E2AD493CC26A6AF0098DAD335BEC0E6237EC545C88714B477A8032080818CAC7EC74475E341E217E74FD78AB06F49C6A14811FE997AFF25856CBF3D5E9D832850C02E38D6F729F60FCEBB505B162C3AB294A0D177511C08C5FF6D604F4A4A9DCB78214FC56912070E575DE77B3F5ECA26E879DAAAE2F111607D561D438F39B12A0418DE7DAC649948B7D61E6E91FC71549600A0CCEC5B9DFF653F277A34CE0BCE698A153C24DA09E01420543A343E124B3FF79EB04077E0CCA52D4131C10EE2BBDE61E199B8D2C880862C80ABCFBFCC99DC9A3514D1910E8C0D38B07D7F1560B6ED29F288A1FC9A99AC9DF88851CF77F01930249822E3E34B9108DCB212DBF3E42AE55AAA9234DAB3D438F4F413B98C0436A7C40834A6BCB5B226CC5804E81F89EE8C6DE8191FBA3612912502BC1D3A092426";
    string la = "0A35043C75BA35A5A4BD4934FA23B8F718118D01D887731A02A0F5ED56D5760C0091BDB836E9A50BEF75CC7325A3D80BA89219D95D43A4C2413A6D2F014F76DB4D005D59FD6C272C15F190DA66329F6C0E7FB0D90CEE6B0AA7512B0FFDB3B72406FA01422FEC0449930948CF8C2D061C4327372229246F881AB372C0405D117CC26FFEC45E93840B5A9F00019C298BA9E859EF87197EA49C2BBF508F9CBD2D0389B275BF075D64DECFCF8BFE705DDB2B03BCFEC39A3F141C8FC2F258DF271657B41C3687122B080474BC254F4EB5651907243B747CC805E43B983F9CBDD296B5CBCCC4E0541D523339A2B125E2CAD70DE2F3D0941DAB43624372B15C66219A22";
    string mu = "076C50DDC5F6834D1CE074E91FE06B616081DEF2CBCB049DFD7FEB54AA154F77BF2DE328362B1FB8D369639396154B10A7834EF39AFEBAA0C64E5810D26F902056C7DEF705264FB60476FFD1B109FFF889D64A7C156C1A32E84E697483D561EED643AD268D89C99C42418EC9E5C14CC2C067CA277DBA9F0CEC84BFDC99AE63A873DF60B71A1BE6C07E60EB8D062D37B25651C52FFF14D37A1957A28381CD408DBD298084D4A41FC8EDFB2470C57B421111CBB99FFE01D51C3777D9FB6B0F60D7F1770B90D0828F4F213C11C93672AB2F7E3904DA14EEFC4E628860E2315B2AEF35A75280CAC98ADB971BC967C4442C0616879C69B64FC47F0892E8A328DBA81E";
    hkey.privatekey.push_back(hex2bit(n));
    hkey.privatekey.push_back(hex2bit(la));
    hkey.privatekey.push_back(hex2bit(mu));
    hkey.publickey.push_back(hex2bit(n));
    hkey.publickey.push_back(hex2bit(hs));

    vector<string> Homo_ciphertext(station_number, "");
    for (size_t i = 0; i < station_number; i++) {
        station_money_lib[i] = i + 1;
    }

    vector<string> selfbit(station_number, {0});
    selfbit[in_id] = 1;
    cout << "bit:\n";
    for (size_t i = 0; i < station_number; i++) {
        printf("%d", (uint8_t)selfbit[i][0]);
    }
    cout << "\n\n";
    for (uint32_t i = 0; i < station_number; i++) {
        if (!Enc_Paillier(selfbit[i], hkey.publickey, Homo_ciphertext[i])) {
            cout << "\n错误！！！\n";
        }
    }
    string money = get_money(Homo_ciphertext, hkey.publickey[0]);
    
    string cost;
    Dec_Paillier(money, hkey.privatekey, cost);
    cout << "cost:" << bit2hex(cost) << endl;

}

#endif


// 参数是 cip 的集合 和 N的平方 数据为比特流
string get_money(vector<string> cip, string N)
{
    bignum_ctx* temp_ctx = BN_CTX_new();

    // ******************************
    BIGNUM* theN = BN_new(); // 得到N
    BN_bin2bn((unsigned char*)N.c_str(), N.length(), theN);

    BIGNUM* temp_N = BN_new();
    BN_mul(temp_N, theN, theN, temp_ctx);// 得到N^2

    // ******************************
    string str_station_value(2, 0);
    BIGNUM* station_value = BN_new();//计算每个站点的价格
    BIGNUM* ret = BN_new();//计算最终结果
    BIGNUM* temp_value = BN_new();
    // ******************************
    for (size_t i = 0; i < station_number; i++)
    {
        str_station_value[0] = station_money_lib[i] >> 8;
        str_station_value[1] = station_money_lib[i] % 256;
        //printf("str_station_value: %d %d\n", (uint8_t)str_station_value[0], (uint8_t)str_station_value[1]);
        BN_bin2bn((unsigned char*)str_station_value.c_str(), str_station_value.length(), station_value); // 对应车站的金额

        string temp;
        for (size_t j = 0; j < 512; j++)
        {
            if (cip[i][j] != 0)
            {
                temp = string(cip[i].begin() + i, cip[i].end());//去除填充的0
                break;
            }
        }
        if (i == 0)
        {
            BN_bin2bn((unsigned char*)temp.c_str(), temp.length(), ret);
            BN_mod_exp(ret, ret, station_value, temp_N, temp_ctx);
            continue;
        }
        BN_bin2bn((unsigned char*)temp.c_str(), temp.length(), temp_value);
        BN_mod_exp(temp_value, temp_value, station_value, temp_N, temp_ctx);
        BN_mod_mul(ret, ret, temp_value, temp_N, temp_ctx);
    }

    unsigned char ret_str[512];
    BN_bn2bin(ret, ret_str);

    BN_free(ret);
    BN_free(temp_N);
    BN_free(station_value);
    BN_free(temp_value);
    BN_CTX_free(temp_ctx);

    string out(512, 0);
    for (size_t i = 0; i < 512; i++) {
        out[i] = ret_str[i];
    }

    return out;
}
#endif
