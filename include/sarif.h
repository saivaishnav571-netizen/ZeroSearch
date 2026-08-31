#ifndef ZEROTRACE_SARIF_H
#define ZEROTRACE_SARIF_H

#include <string>
#include <vector>

#include "finding.h"

namespace zerotrace {

std::string build_sarif_report(
    const std::vector<Finding>& findings
);

}

#endif