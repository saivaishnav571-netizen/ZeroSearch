#ifndef ZEROTRACE_REDACTOR_H
#define ZEROTRACE_REDACTOR_H

#include <string>

namespace zerotrace {

std::string redact_secret(const std::string& secret);

}

#endif