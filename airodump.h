#ifndef AIRODUMP_H
#define AIRODUMP_H

#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include <mutex>
#include <thread>

// Radiotap Header 구조체
struct RadiotapHeader {
    uint8_t version; 
    uint8_t pad;
    uint16_t length;
    uint32_t presentFlags;
};

// BeaconInfo 구조체
struct BeaconInfo {
    std::string bssid;
    std::string essid;
};

// Airodump 클래스
class Airodump {
public:
    Airodump(const std::string& interface);
    ~Airodump();
    void startCapture();
    void displayData();

private:
    std::string interface;
    std::map<std::string, std::string> bssidToEssid; // BSSID -> ESSID 매핑
    std::mutex dataMutex; // 맵 접근을 위한 뮤텍스
    bool stopThreads; // 쓰레드 종료 플래그

    void captureThread();
    void parsePacket(const uint8_t* packet, size_t length);
};

#endif // AIRODUMP_H

