#include "airodump.h"
#include <iostream>
#include <pcap.h>  // libpcap 헤더 파일
#include <cstring>
#include <unistd.h>

// Airodump 클래스 생성자
Airodump::Airodump(const std::string& interface) 
    : interface(interface), stopThreads(false) {} // 네트워크 인터페이스 이름 설정 및 쓰레드 종료 플래그 초기화

// Airodump 클래스 소며자자
Airodump::~Airodump() {
    stopThreads = true; // 쓰레드 종료 플래그
}

// 캡처 및 출력 쓰레드를 시작
void Airodump::startCapture() {
    std::thread captureThread(&Airodump::captureThread, this); // 캡처 쓰레드
    std::thread displayThread(&Airodump::displayData, this); // 데이터 출력 쓰레드

    captureThread.join();
    displayThread.join();
}

// 네트워크 패킷을 캡처하는 쓰레드
void Airodump::captureThread() {
    char errbuf[PCAP_ERRBUF_SIZE]; // 오류 처리 버퍼 생성
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf); // 네트워크 인터페이스 오픈
    if (!handle) { // 핸들 생성 실패 시
        std::cerr << "Error opening device: " << errbuf << std::endl; // 오류 메시지 출력
        return; // 함수 종료
    }

    while (!stopThreads) { // 쓰레드 종료 플래그가 false일 동안 계속 반복
        struct pcap_pkthdr* header; // 패킷 헤더 구조체
        const uint8_t* packet; // 패킷 데이터
        int res = pcap_next_ex(handle, &header, &packet); // 다음 패킷 가져오기
        if (res == 0) continue; // 타임아웃 발생 시 다음 반복으로
        if (res == -1 || res == -2) break; // 에러 또는 종료 요청 시 루프 완ㄹㄹ

        parsePacket(packet, header->len); // 패킷 파싱 함수 호출
    }

    pcap_close(handle); // 캡처 핸들 닫기
}

// MAC 주소가 깨져서 인코딩하는 부분을 "xx:xx:xx:xx:xx:xx" 형식으로 변환하는 함수 추가함 이따가 parsePacket에도 추가해야함 
std::string formatMacAddress(const uint8_t* mac) {
    char buffer[18]; // MAC 주소 출력 버퍼 (17문자 + null)
    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); // MAC 주소 포맷팅
    return std::string(buffer); // 프린트
}

// 패킷 데이터를 파싱하는 함수
void Airodump::parsePacket(const uint8_t* packet, size_t length) {

    // 이부분은 잘 모르겠어서 pcap이랑 airodump-ng 및 chatGPT 참고함

    if (length < sizeof(RadiotapHeader)) return; // RadiotapHeader보다 작은 패킷은 무시

    const RadiotapHeader* radiotap = reinterpret_cast<const RadiotapHeader*>(packet); // RadiotapHeader로 캐스팅
    if (radiotap->version != 0) return; // 유효한 RadiotapHeader인지 확인

    size_t offset = radiotap->length; // RadiotapHeader 길이 계산
    if (offset >= length) return; // 패킷 길이를 초과하면 무시

    const uint8_t* frame = packet + offset; // 802.11 프레임 데이터 시작 위치


    // 여기서 부터 다시 와이어샤크 확인하면서 작성

    if (frame[0] != 0x80) return; // Beacon Frame(0x80)인지 확인

    const uint8_t* bssid = frame + 10; // BSSID 위치 (MAC 헤더의 10번째 바이트부터 6바이트)


    std::string formattedBssid = formatMacAddress(bssid); // BSSID를 MAC 주소 형식으로 변환 함수 추가함


    const uint8_t* tags = frame + 36; // 태그 필드 시작 위치 (MAC 헤더 이후) 와이어샤크에서 그냥 카운트
    std::string essid;

    while (tags + 2 < packet + length) { // 태그가 패킷 범위를 초과하지 않을 동안 반복
        uint8_t tagNumber = tags[0]; // 태그 번호 (코드 리뷰에서는 이것도 구조체에 넣어야하지만 자꾸 오류나서 일단 2개만 추출 )
        uint8_t tagLength = tags[1]; // 태그 길이
        const uint8_t* tagData = tags + 2; // 태그 데이터 시작 위치

        if (tagNumber == 0) { // ESSID 태그 확인
            essid = std::string(reinterpret_cast<const char*>(tagData), tagLength); // ESSID 데이터 추출
        }

        tags += 2 + tagLength; // 다음 태그로 이동
        if (tags > packet + length) break; // 태그가 패킷 범위를 초과하면 종료
    }

    if (!formattedBssid.empty() && !essid.empty()) { // BSSID와 ESSID가 유효하면
        std::lock_guard<std::mutex> lock(dataMutex); // 맵 접근을 위한 뮤텍스 잠금
        bssidToEssid[formattedBssid] = essid; // BSSID와 ESSID 매핑
    }
}

// BSSID와 ESSID 데이터를 출력하는 함수
void Airodump::displayData() {
    while (!stopThreads) { // 쓰레드 종료 플래그가 false일 동안 반복
        {
            std::lock_guard<std::mutex> lock(dataMutex); // 맵 접근을 위한 뮤텍스 잠금
            system("clear"); // 화면 지우기
            std::cout << "BSSID\t\t\tESSID" << std::endl; // 헤더 출력
            for (const auto& [bssid, essid] : bssidToEssid) { // BSSID -> ESSID 매핑 출력
                std::cout << bssid << "\t" << essid << std::endl;
            }
        }
        sleep(1); // 1초 대기 후 다음 출력 (2초는 너무 느림)
    }
}
