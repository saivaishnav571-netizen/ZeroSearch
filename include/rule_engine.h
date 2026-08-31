#ifndef ZEROTRACE_RULE_ENGINE_H
#define ZEROTRACE_RULE_ENGINE_H

#include <string>
#include <vector>

#include "finding.h"
#include "rule.h"

namespace zerotrace {

std::vector<DetectionRule> create_default_rules();

std::vector<Finding> apply_rules(
    const std::string& file,
    const std::string& content
);

}

#endif