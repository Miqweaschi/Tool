#include <iostream>
#include <string>
#include <vector>

struct HashMapping {
    std::string_view prefisso;
    std::string_view nome_hash;
};

int main(int argc, char* argv[]) {
    std::string hash = argv[1];
    std::cout << "Hash inserito: " << hash << std::endl;
    std::vector<HashMapping> prefissi = {
        {"$2b$", "bcrypt"},
        {"$argon2id$", "Argon2id"},
        {"$apr1$", "Apache MD5"},
        {"*", "MySQL5"}
    };
    switch(hash.length()) {
        case 32:
            std::cout << "Tipo di hash: MD5" << std::endl;
            break;
        case 40:
            std::cout << "Tipo di hash: SHA-1" << std::endl;
            break;
        case 64:
            std::cout << "Tipo di hash: SHA-256" << std::endl;
            break;
        case 128:
            std::cout << "Tipo di hash: SHA-512" << std::endl;
            break;
        default:
            for (int i = 0; i < prefissi.size(); ++i) {
                if (hash.rfind(prefissi[i].prefisso, 0) == 0) {
                    std::cout << "Tipo di hash: " << prefissi[i].nome_hash << std::endl;
                    break;
                }
            }   
            break;
        }
    return 0;
}