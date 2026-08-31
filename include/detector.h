#ifndef ZEROTRACE_DETECTOR_H
#define ZEROTRACE_DETECTOR_H

#include <string>
#include <unordered_set>
#include <vector>

#include "finding.h"

namespace zerotrace {

std::vector<Finding> detect_secrets(
    const std::string& file,
    const std::string& content,
    const std::unordered_set<std::string>& enabled_rules
);

}

#endif