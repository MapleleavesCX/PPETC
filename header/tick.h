#pragma once
#include <string>
#include <iostream>
using namespace std;

// 工作模式 CTR计时函数
class tick {
private:
    uint8_t remember[16];
public:
    string counter;

    tick() {
        counter = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        for (uint8_t i = 0; i < 15; i++) {
            remember[i] = 0;
        }
        remember[15] = 1;
    }
    tick(size_t num) {

        char buffer[33];
        snprintf(buffer, sizeof(buffer), "%032x", num);
        counter = hex2bit(buffer);

        for (uint8_t i = 0; i < 15; i++) {
            remember[i] = 0;
        }
        remember[15] = 1;
    }

    bool add1() {

        counter[15] = (uint8_t)counter[15] + 1;
        remember[15] = 1;

        for (uint8_t x = 15; x > 0; x--) {
            if (remember[x] == 1 && (uint8_t)counter[x] == 0)
            {
                counter[x - 1]++;
                remember[x - 1] = 1;
                remember[x] = 0;
            }
        }

        if (remember[0] == 1 && (uint8_t)counter[0] == 0)
        {
            printf("Tick Error!!!\n");
            return false;
        }

        return true;
    }

    void printT() {
        printf("time: ");
        for (uint8_t j = 0; j < 16; j++) {
            printf("%3d ", (uint8_t)counter[j]);
        }
        printf("\n");
    }
};


/*uint64_t end = 256*256 * 256;

tick C;
uint64_t i = 0;
while (true) {
    C.add1();
    i++;
    if (((i % 256) > 254) || ((i % 256) < 2)) {
        C.printT();
    }
    if (i == end)
        break;
}*/