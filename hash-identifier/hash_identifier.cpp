#include <iostream>
#include <string>
#include <vector>

struct HashMapping
{
    std::string_view prefisso;
    std::string_view nome_hash;
    std::string_view descrizione;
};

int main(int argc, char *argv[])
{
    std::string hash = argv[1];
    std::cout << "Hash inserito: " << hash << std::endl;
    std::vector<HashMapping> prefissi = {
        {"$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"},
        {"$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"},
        {"$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"},
        {"$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"},


        {"$argon2id$", "Argon2id", "modern PHC string, the current standard"},
        {"$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"},
        {"$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"},
        

        {"$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"},
        {"$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"},
        {"$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"},

        {"$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"},

        {"$y$", "yescrypt", "PHC string, modern Linux crypt successor"},

        {"$P$", "phpass", "WordPress / phpBB password hash"},
        {"$H$", "phpass", "phpBB-style phpass variant"},

        {"$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"},

    
        {"$7$", "scrypt", "scrypt PHC-style hash"},

        {"pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"},
        {"pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"},
        {"bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"},
        {"argon2$", "Django Argon2", "Django Argon2 wrapper"},

        {"{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"},
        {"{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"},
        {"{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"},
        {"{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"},
        {"{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"},


        {"*", "MySQL5"}
    };
    switch (hash.length())
    {
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
        for (int i = 0; i < prefissi.size(); ++i)
        {
            if (hash.rfind(prefissi[i].prefisso, 0) == 0)
            {
                std::cout << "Tipo di hash: " << prefissi[i].nome_hash << " - " << prefissi[i].descrizione << std::endl;
                break;
            }
        }
        break;
    }
    return 0;
}