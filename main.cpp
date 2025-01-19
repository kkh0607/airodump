#include "airodump.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }

    std::string interface = argv[1];
    Airodump airodump(interface);
    airodump.startCapture();

    return 0;
}

