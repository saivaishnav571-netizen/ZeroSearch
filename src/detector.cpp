#include "detector.h"
#include "entropy.h"
#include "rule_engine.h"

namespace zerotrace {

static Severity calculate_severity(int confidence) {

    if (confidence >= 90) {
        return Severity::CRITICAL;
    }

    if (confidence >= 75) {
        return Severity::HIGH;
    }

    if (confidence >= 50) {
        return Severity::MEDIUM;
    }

    return Severity::LOW;
}

std::vector<Finding> detect_secrets(
    const std::string& file,
    const std::string& content
) {

    std::vector<Finding> findings =
        apply_rules(file, content);

    for (Finding& finding : findings) {

        const double entropy =
            calculate_entropy(finding.matched_text);

        int confidence = finding.confidence;

        if (entropy >= 3.5) {
            confidence += 10;
        }

        if (entropy >= 4.0) {
            confidence += 5;
        }

        if (confidence > 100) {
            confidence = 100;
        }

        finding.entropy = entropy;
        finding.confidence = confidence;
        finding.severity = calculate_severity(confidence);
    }

    return findings;
}

}