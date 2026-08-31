#ifndef ZEROTRACE_RULE_H
#define ZEROTRACE_RULE_H

#include <regex>
#include <string>

namespace zerotrace {

struct DetectionRule {
    std::string name;
    std::string description;
    std::regex pattern;
    int base_confidence;
};

}

#endif