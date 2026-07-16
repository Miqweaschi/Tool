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
            std::cout << "Tipo di hash (Potrebbe essere): MD5, questo perchè ha 32 caratteri" << std::endl;
            break;
        case 40:
            std::cout << "Tipo di hash (Potrebbe essere): SHA-1, questo perchè ha 40 caratteri" << std::endl;
            break;
        case 64:
            std::cout << "Tipo di hash (Potrebbe essere): SHA-256, questo perchè ha 64 caratteri" << std::endl;
            break;
        case 128:
            std::cout << "Tipo di hash (Potrebbe essere): SHA-512, questo perchè ha 128 caratteri" << std::endl;
            break;
        default:
            for (int i = 0; i < prefissi.size(); ++i) {
                if (hash.rfind(prefissi[i].prefisso, 0) == 0) {
                    std::cout << "Tipo di hash: " << prefissi[i].nome_hash << ", questo perchè ha " << prefissi[i].prefisso << " come prefisso" << std::endl;
                    break;
                }
            }   
            break;
        }
    return 0;
}