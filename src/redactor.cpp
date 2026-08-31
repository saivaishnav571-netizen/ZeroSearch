#include "redactor.h"

namespace zerotrace {

std::string redact_secret(const std::string& secret) {

    const std::size_t length = secret.length();

    if (length <= 8) {
        return "********";
    }

    const std::size_t visible_characters = 4;

    const std::string prefix =
        secret.substr(0, visible_characters);

    const std::string suffix =
        secret.substr(length - visible_characters);

    return prefix + "********" + suffix;
}

}