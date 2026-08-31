#ifndef ZEROTRACE_RULE_ENGINE_H
#define ZEROTRACE_RULE_ENGINE_H

#include <string>
#include <unordered_set>
#include <vector>

#include "finding.h"
#include "rule.h"

namespace zerotrace {

std::vector<DetectionRule> create_default_rules();

std::unordered_set<std::string> load_enabled_rules(
    const std::string& path
);

std::vector<DetectionRule> load_custom_rules(
    const std::string& path
);

std::vector<Finding> apply_rules(
    const std::string& file,
    const std::string& content,
    const std::unordered_set<std::string>& enabled_rules,
    const std::vector<DetectionRule>& custom_rules
);

}

#endif