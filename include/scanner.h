#ifndef ZEROTRACE_SCANNER_H
#define ZEROTRACE_SCANNER_H

#include <string>
#include <vector>

namespace zerotrace {

std::vector<std::string> scan_directory(const std::string& path);

}

#endif  