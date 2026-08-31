#ifndef ZEROTRACE_FINDING_H
#define ZEROTRACE_FINDING_H

#include <string>

namespace zerotrace {

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct Finding {
    std::string file;
    int line;
    std::string type;
    std::string matched_text;

    double entropy;

    Severity severity;
    int confidence;
};

}

#endif