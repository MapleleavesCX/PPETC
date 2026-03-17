
#include<thread>

//////////////////////////可修改参数///////////////////////////////////////////////////

#include"C:/Users/-ASUS-/Desktop/ETC/header/allheader.h"
#include"C:/Users/-ASUS-/Desktop/ETC/header/winsock.h"
const size_t station_number = 256;//要与ring_sign.h里的station_num数值统一
uint32_t tpnum = 8;//线程数目
string TSPkey = "1234567887654321";//所有收费站共用的对称密钥
string TSPiv = "0100101010101010";//所有收费站共用的IV


/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////


//从TCP本部获取到本地站点的环签名公钥私钥
ring_sig_Key ringkey;
size_t nnn = station_number + 2;// 站点数加上站id加上when
vector<string> Homo_ciphertext;//全局变量存储同态密文，方便多线程输出
vector<string> station_money_lib(station_number, "");//收费金额列表

void for_paillier(vector<string> hpk, vector<string> selfbit,
    uint32_t start, uint32_t end);

void Thread_1(vector<string> hpk, vector<string> selfbit);
void Thread_2(vector<string> hpk, vector<string> selfbit);
void Thread_4(vector<string> hpk, vector<string> selfbit);
void Thread_8(vector<string> hpk, vector<string> selfbit);

// 参数是同态密文的集合cip 和 模数 N , 数据为比特流
string get_money(vector<string> cip, string N);

int ETC_station_in(uint32_t mynumber);

int ETC_station_out(uint32_t mynumber);

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

int main() {

    
    cout << ">>>>ETC全部站点数目：" << station_number << endl;
    cout << ">>>>开启线程数目：" << tpnum << endl << endl;
    cout << "*正在生成环签名密钥...";
    ringkey = ring_generate();
    cout << "完成\n";
    cout << "*生成费用价目列表（收费金额初始化）...";
    for (size_t i = 0; i < station_number; i++) {
        string m(2, 0);
        size_t mm = (i + 1) * 100;
        m[0] = (mm) >> 8;
        m[1] = (mm) % 256;
        station_money_lib[i] = bit2hex(m);
    }
    cout << "完成\n";

    uint32_t in_id, out_id;//编辑出站入站ID

    string chose = "y";
    while (chose == "y") {
        cout << "\n请输入 入口收费站id：";
        cin>>in_id;
        cout << "请输入 出口收费站id：";
        cin>>out_id;

        if (ETC_station_in(in_id) == 0) {
            return 0;
        }

        if (ETC_station_out(out_id) == 0) {
            return 0;
        }
        cout << "\n是否继续？[y/n] ";
        cin >> chose;
    }
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

int ETC_station_in(uint32_t mynumber) {

    cout << "\n>>>>进站ETC收费站点ID：" << mynumber << endl;

    //初始化套接字
    winsock instation;

    cout << "********************************\n\n";
    Homo_ciphertext.resize(nnn);//重设长度


    instation.set_server(8080);

    // 开始监听连接请求
    SOCK car;
    instation.listening_to_client(car);


    cout << "\n****ETC协议启动****\n";
    auto startall = chrono::system_clock::now();


    printf("正在建立安全信道...");
    auto start = chrono::system_clock::now();
    //*****************************************************
    
    if (!car.server_secure_channel_set()) {
        cout << "客户端断开连接\n";
        return 0;
    }
    cout << "成功！\n";
    //*****************************************************
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    uint64_t tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    cout << "*等待对方发送...";
    start = chrono::system_clock::now();
    //*****************************************************
    string Mbit = car.secure_receivefrom(832);
    if (Mbit == "") {
        cout << "客户端断开连接\n";
        return 0;
    }
    cout << "成功收到信息！\n";
    cout << "*信息长度：" << Mbit.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    string randp, randq;
    vector<string> hpk;
    cout << "*正在截取对应同态公钥...";
    start = chrono::system_clock::now();
    //*****************************************************
    hpk.push_back(Mbit.substr(0, 256));
    hpk.push_back(Mbit.substr(256, 512));

    //cout << "hpk[0] = \n" << bit2hex(hpk[0]) << endl;
    //cout << "hpk[1] = \n" << bit2hex(hpk[1]) << endl;


    randp = Mbit.substr(768, 32);
    randq = Mbit.substr(800, 32);
    cout << "完成！\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    //用得到的同态公钥加密本地bit串
    cout << "*正在同态加密 线程数：" << tpnum << " ...";
    start = chrono::system_clock::now();
    //*****************************************************
    vector<string> selfbit(nnn, { 0 });
    selfbit[mynumber] = { 1 };
    string id(2, 0);
    id[0] = mynumber >> 8;
    id[1] = mynumber % 256;
    selfbit[station_number] = id;//本站id号
    selfbit[station_number + 1] = get_when();//进站时间

    //多线程同态加密
    switch (tpnum) {
    case 1:
        Thread_1(hpk, selfbit);
        break;
    case 2:
        Thread_2(hpk, selfbit);
        break;
    case 4:
        Thread_4(hpk, selfbit);
        break;
    case 8:
        Thread_8(hpk, selfbit);
        break;
    default:
        cout << "Thread_？： 不支持的线程数量\n";
        return 0;
    }

    //把加密得到的所有密文合并
    string Homo_c = "";
    for (size_t i = 0; i < nnn; i++) {
        Homo_c += fill0(Homo_ciphertext[i], 512);
        
    }

   /* for (size_t i = 0; i < station_number; i++) {
        cout << "\n第" << i << "段密文：\n" << bit2hex(Homo_ciphertext[i]) << endl;
    }*/

    Homo_c = Homo_c + randp + randq;
    cout << "结束\n";
    cout << "*同态密文长度：" << Homo_c.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    //对 Homo_ciphertext || randp || randq 进行环签名
    cout << "*正在环签名...";
    start = chrono::system_clock::now();
    //*****************************************************
    string sign2;
    string sign1[station_number];
    ring_sig(Homo_c, sign1, sign2, ringkey.publickey,
        ringkey.privatekey[mynumber], mynumber);

    //合并签名
    start = chrono::system_clock::now();

    string signall = "";
    for (size_t i = 0; i < station_number; i++) {
        signall += sign1[i];
    }
    signall += sign2;
    cout << "结束\n";
    cout << "*签名长度：" << signall.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    Homo_c += signall;//合并密文与签名


    // 用收费站内部的共同对称密钥加密消息
    start = chrono::system_clock::now();
    //*****************************************************
    cout << "正在进行站内信息加密...";
    string C;
    if (!sm4work(CTR_enc, C, Homo_c, TSPkey, TSPiv)) {
        return 0;
    }
    cout << "完成！\n";
    cout << "*加密密文总长度：" << Homo_c.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    //发送内容
    start = chrono::system_clock::now();
    //*****************************************************
    cout << "正在发送密文...";
    if (!car.secure_sendto(C)) {
        return 0;
    }
    cout << "成功！\n";
    cout << "*发送信息总长度：" << Homo_c.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    auto endall = chrono::system_clock::now();
    auto durationall = chrono::duration_cast<chrono::microseconds>(endall - startall);
    uint64_t ttall = durationall.count();
    cout << "进站ETC交互  用时：" << (double)((double)ttall / 1000) << " ms\n\n";



    Homo_ciphertext.clear();//清理内部元素，以便下一个访问

    return 1;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////


int ETC_station_out(uint32_t mynumber) {

    cout << ">>>>出站ETC收费站点ID：" << mynumber << endl;



    //初始化套接字
    winsock outstation;

    cout << "********************************\n\n";
    outstation.set_server(8080);

    // 开始监听连接请求
    SOCK car;
    outstation.listening_to_client(car);


    cout << "\n****ETC协议启动****\n";

    // 开始计时
    auto startall = chrono::system_clock::now();



    printf("正在建立安全信道...");
    auto start = chrono::system_clock::now();
    //*****************************************************
    // 接收客户端发来的请求 REQ||sm2_pk0||sm2_pk1
    if (!car.server_secure_channel_set()) {
        cout << "客户端断开连接\n";
        return 0;
    }
    cout << "成功！\n";
    //*****************************************************
    auto end = chrono::system_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    uint64_t tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    cout << "*等待对方发送...";
    start = chrono::system_clock::now();
    //*****************************************************
    string Mbit = car.secure_receivefrom(
        768 + 512 * (station_number + 2) + 
        128 * (station_number + 1) + 64);
    if (Mbit == "") {
        cout << "接收失败\n";
        return 0;
    }
    cout << "成功收到信息！\n";
    cout << "*信息长度：" << Mbit.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";

    //收到 hpk || HC
    vector<string> hpk;
    string HC;
    cout << "*正在截取对应同态公钥与密文...";
    start = chrono::system_clock::now();
    //*****************************************************
    hpk.push_back(Mbit.substr(0, 256));
    hpk.push_back(Mbit.substr(256, 512));
    HC = Mbit.substr(768);
    cout << "完成！\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";

    //解密HC
    start = chrono::system_clock::now();
    //*****************************************************
    cout << "正在进行解密...";
    string homo_rand_sign;
    if (!sm4work(CTR_dec, homo_rand_sign, HC, TSPkey, TSPiv)) {
        return 0;
    }
    cout << "完成！\n";
    cout << "*解密出明文总长度：" << homo_rand_sign.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";

    cout << "正在进行截取对应信息...";
    start = chrono::system_clock::now();
    //*****************************************************
    //同态密文截取
    string homo_c = homo_rand_sign.substr(0, 512 * nnn);
    vector<string> homo_ciphertext(station_number);

    for (size_t i = 0; i < station_number; i++) {
        homo_ciphertext[i] = homo_c.substr(512 * i, 512);
        //cout << "\n第" << i << "段密文：\n" << bit2hex(homo_ciphertext[i]) << endl;
    }

    string homo_in_id = homo_c.substr(512 * station_number, 512);
    string homo_in_when = homo_c.substr(512 * (station_number + 1), 512);
    //随机数截取
    string randp = homo_rand_sign.substr(512 * nnn, 32);
    string randq = homo_rand_sign.substr(512 * nnn + 32, 32);
    string ringsign = homo_rand_sign.substr(512 * nnn + 64, 65664);
    //签名截取
    string sign1[station_number], sign2;
    for (size_t i = 0; i < station_number; i++) {
        sign1[i] = ringsign.substr(128 * i, 128);
    }
    sign2 = ringsign.substr(ringsign.length() - 128, 128);
    cout << "完成！\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";

    //验签
    start = chrono::system_clock::now();
    //*****************************************************
    cout << "正在验签...";
    if (!verify_sig(homo_c + randp + randq, sign1, sign2, ringkey.publickey)) {
        cout << "未通过！\n";
        return 0;
    }
    cout << "通过！\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    //同态密文处理
    cout << "同态密文处理...";
    start = chrono::system_clock::now();
    //*****************************************************
    string homo_cost = fill0(get_money(homo_ciphertext, hpk[0]), 512);

    cout << "结束" << endl;
    cout << "计算同态密文结果 长度：" << homo_cost.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    //同态加密本地站id和出站时间
    string homo_out_id;
    string homo_out_when;
    string id(2, 0);
    id[0] = mynumber >> 8;
    id[1] = mynumber % 256;
    if (!Enc_Paillier(id, hpk, homo_out_id) ||
        !Enc_Paillier(get_when(), hpk, homo_out_when)) {
        return 0;
    }



    cout << "环签名...";
    start = chrono::system_clock::now();
    //*****************************************************
    //对费用的签名
    string sign_cost1[station_number], sign_cost2;
    ring_sig(homo_cost, sign_cost1, sign_cost2, ringkey.publickey, 
        ringkey.privatekey[mynumber], mynumber);
    string sign_cost = "";
    for (size_t i = 0; i < station_number; i++) {
        sign_cost += sign_cost1[i];
    }
    sign_cost += sign_cost2;

    //对账单信息的签名
    string bill = homo_in_id + homo_in_when +
        fill0(homo_out_id, 512) + fill0(homo_out_when, 512) + randp + randq;
    string sign_bill1[station_number], sign_bill2;
    ring_sig(bill, sign_bill1, sign_bill2, ringkey.publickey, 
        ringkey.privatekey[mynumber], mynumber);
    string sign_bill = "";
    for (size_t i = 0; i < station_number; i++) {
        sign_bill += sign_bill1[i];
    }
    sign_bill += sign_bill2;
    cout << "结束" << endl;
    cout << "*sign_cost长度：" << sign_cost.length() << " 字节\n";
    cout << "*sign_bill长度：" << sign_bill.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    //发送 Φ(cost) || sign_cost || bill || sign_bill
    start = chrono::system_clock::now();
    //*****************************************************
    cout << "发送 最终账单信息...";
    string sendbill = homo_cost + sign_cost + bill + sign_bill;
    car.secure_sendto(sendbill);
    cout << "成功" << endl;
    cout << "*账单信息长度：" << sendbill.length() << " 字节\n";
    //*****************************************************
    end = chrono::system_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(end - start);
    tt = duration.count();
    cout << "用时：" << (double)((double)tt / 1000) << " ms\n\n";


    auto endall = chrono::system_clock::now();
    auto durationall = chrono::duration_cast<chrono::microseconds>(endall - startall);
    uint64_t ttall = durationall.count();
    cout << "本次ETC交互结束  用时：" << (double)((double)ttall / 1000) << " ms\n\n";



    return 1;

}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////


string get_money(vector<string> cip, string N)
{

    BN_CTX* ctx = BN_CTX_new();

    // ******************************
    BIGNUM* the_N = BN_new(); // 得到N
    BN_hex2bn(&the_N, bit2hex(N).c_str());

    BIGNUM* N2 = BN_new();
    BN_mul(N2, the_N, the_N, ctx);// 得到N^2

    // ******************************

    BIGNUM* MONEY = BN_new();
    BN_hex2bn(&MONEY, station_money_lib[0].c_str());

    BIGNUM* COST = BN_new();
    BN_hex2bn(&COST, bit2hex(cip[0]).c_str());
    BN_mod_exp(COST, COST, MONEY, N2, ctx);

    BIGNUM* TEMP = BN_new();
    for (size_t i = 1; i < station_number; i++) {

        BN_hex2bn(&MONEY, station_money_lib[i].c_str());

        unsigned char temp[512];
        for (size_t j = 0; j < 512; j++) {
            temp[j] = cip[i][j];
        }
        BN_bin2bn(temp, 512, TEMP);

        BN_mod_exp(TEMP, TEMP, MONEY, N2, ctx);

        BN_mod_mul(COST, COST, TEMP, N2, ctx);
    }
    string cost = hex2bit(BN_bn2hex(COST));
    BN_free(the_N);
    BN_free(N2);
    BN_free(MONEY);
    BN_free(COST);
    BN_free(TEMP);
    BN_CTX_free(ctx);
    return cost;
}

void for_paillier(vector<string> hpk, vector<string> selfbit,
    uint32_t start, uint32_t end) {
    bool k;
    for (uint32_t i = start; i < end; i++) {
        k = Enc_Paillier(selfbit[i], hpk, Homo_ciphertext[i]);
        if (!k) {
            cout << "\n错误！！！\n";
        }
    }

}

//多线程区 int====================================================================
void Thread_1(vector<string> hpk, vector<string> selfbit) {
    thread t1(for_paillier, hpk, selfbit, 0, nnn);
    t1.join();
}

void Thread_2(vector<string> hpk, vector<string> selfbit) {
    thread t1(for_paillier, hpk, selfbit, 0, nnn / 2);
    thread t2(for_paillier, hpk, selfbit, nnn / 2, nnn);
    t1.join();
    t2.join();
}

void Thread_4(vector<string> hpk, vector<string> selfbit) {
    thread t1(for_paillier, hpk, selfbit, 0, nnn / 4);
    thread t2(for_paillier, hpk, selfbit, nnn / 4, nnn / 2);
    thread t3(for_paillier, hpk, selfbit, nnn / 2, nnn * 3 / 4);
    thread t4(for_paillier, hpk, selfbit, nnn * 3 / 4, nnn);
    t1.join();
    t2.join();
    t3.join();
    t4.join();
}

void Thread_8(vector<string> hpk, vector<string> selfbit) {
    thread t1(for_paillier, hpk, selfbit, 0, nnn / 8);
    thread t2(for_paillier, hpk, selfbit, nnn / 8, nnn / 4);
    thread t3(for_paillier, hpk, selfbit, nnn / 4, nnn * 3 / 8);
    thread t4(for_paillier, hpk, selfbit, nnn * 3 / 8, nnn / 2);
    thread t5(for_paillier, hpk, selfbit, nnn / 2, nnn * 5 / 8);
    thread t6(for_paillier, hpk, selfbit, nnn * 5 / 8, nnn * 3 / 4);
    thread t7(for_paillier, hpk, selfbit, nnn * 3 / 4, nnn * 7 / 8);
    thread t8(for_paillier, hpk, selfbit, nnn * 7 / 8, nnn);
    t1.join();
    t2.join();
    t3.join();
    t4.join();
    t5.join();
    t6.join();
    t7.join();
    t8.join();
}
