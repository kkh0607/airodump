# airodump
not finished

## 구현한 기능 리스트

1. RadioTapHeader 확인
2. Beacon Frame 확인
3. BSSID 태그 확인
4. ESSID 태그 확인
5. BSSID를 키로 ESSID 맵핑
6. 2개의 쓰레드 생성 (1는 데이터 맵핑, 2는 프린트)
7. 혹시 몰라서 mutex 걸기 (쓰레드 2개가 둘다 맵에 접근하기 때문)
