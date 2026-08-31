#include <iostream>
#include <string>
#include <vector>

#include "scanner.h"

int main(int argc, char* argv[]) {

    std::cout << "=================================\n";
    std::cout << "          ZeroTrace\n";
    std::cout << "   Secret Detection Engine\n";
    std::cout << "=================================\n\n";

    if (argc < 2) {
        std::cout << "Usage: zerotrace scan <directory>\n";
        return 1;
    }

    std::string command = argv[1];

    if (command == "scan") {

        if (argc < 3) {
            std::cout << "Error: directory path is required.\n";
            std::cout << "Usage: zerotrace scan <directory>\n";
            return 1;
        }

        std::string path = argv[2];

        std::cout << "Scanning: " << path << "\n\n";

        std::vector<std::string> files =
            zerotrace::scan_directory(path);

        std::cout << "Files found: " << files.size() << "\n";

        return 0;
    }

    std::cout << "Unknown command: " << command << "\n";
    std::cout << "Usage: zerotrace scan <directory>\n";

    return 1;
}