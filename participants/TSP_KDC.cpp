#include"C:/Users/-ASUS-/Desktop/ETC/header/allheader.h"
#include"C:/Users/-ASUS-/Desktop/ETC/header/winsock.h"

/////////////////////////////////////////////////////////////////////////////////////////
const size_t station_number = 128;//要与ring_sign.h里的station_num数值统一
int port = 8000;
/////////////////////////////////////////////////////////////////////////////////////////


int KDC();


int main() {
    
    cout << ">>>>ETC全部站点数目：" << station_number << endl;
    KDC();
    
}

int KDC() {

    cout << "****TSP密钥分发中心****\n\n";

    cout << "生成待分发密钥...";
    //从TCP本部获取到本地站点的环签名公钥私钥
    ring_sig_Key ringkey = ring_generate();
    // 公钥单个长度：247
    // 私钥单个长度：887

    string tspkey = randstr(0, 255, 16);
    string tspiv = randstr(0, 255, 16);
    cout << "完成！\n";

    string pk;
    for (size_t i = 0; i < station_number; i++) {
        pk += ringkey.publickey[i];
    }
    cout << "开始>>>\n";
    //初始化套接字
    winsock kdc;
    kdc.set_server(port);
    while (true) {

        cout << "\n********************************\n\n";

        SOCK station;
        //监听
        kdc.listening_to_client(station);
        
        //等待接收来访的站id
        cout << "等待接收来访的站id\n";
        string station_id = station.receivefrom();
        if (station_id == "") {
            cout << "接收失败！\n";
            continue;
        }
        uint8_t h = station_id[0];
        uint8_t l = station_id[1];
        size_t id = ((size_t)h << 8) + (size_t)l;
        cout << "接收成功！\n";
        printf("来访id = %d\n", id);

        station.sendto(tspkey + tspiv + ringkey.privatekey[id] + pk);

    }
}