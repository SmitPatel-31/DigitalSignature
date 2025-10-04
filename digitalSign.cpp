// Simple CLI for Ed25519 keygen, signing, and verification using OpenSSL EVP.
// Build (Linux/Mac):
//   g++ -std=c++17 ed25519_digital_signatures.cpp -o dsign -lcrypto
// Build (Windows MSYS2/MinGW):
//   g++ -std=c++17 ed25519_digital_signatures.cpp -o dsign.exe -lcrypto
// Usage:
//   Generate keys:   ./dsign gen-key private.pem public.pem
//   Sign a file:     ./dsign sign private.pem input.bin signature.sig
//   Verify a file:   ./dsign verify public.pem input.bin signature.sig

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

void openssl_init() {
    ERR_load_crypto_strings();
}

void openssl_cleanup() {
    ERR_free_strings();
}

void print_last_error(const std::string &prefix) {
    char buf[256];
    unsigned long err = ERR_get_error();
    if (err) {
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << prefix << ": " << buf << "\n";
    } else {
        std::cerr << prefix << "\n";
    }
}

bool write_private_key_pem(EVP_PKEY *pkey, const std::string &path) {
    FILE *fp = fopen(path.c_str(), "wb");
    if (!fp) { std::perror("fopen private"); return false; }
    bool ok = PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp);
    if (!ok) { print_last_error("PEM_write_PrivateKey failed"); }
    return ok;
}

bool write_public_key_pem(EVP_PKEY *pkey, const std::string &path) {
    FILE *fp = fopen(path.c_str(), "wb");
    if (!fp) { std::perror("fopen public"); return false; }
    bool ok = PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    if (!ok) { print_last_error("PEM_write_PUBKEY failed"); }
    return ok;
}

bool load_private_key(const std::string &path, EVP_PKEY **out) {
    *out = nullptr;
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) { std::perror("fopen private"); return false; }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) { print_last_error("PEM_read_PrivateKey failed"); return false; }
    *out = pkey;
    return true;
}

bool load_public_key(const std::string &path, EVP_PKEY **out) {
    *out = nullptr;
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) { std::perror("fopen public"); return false; }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!pkey) { print_last_error("PEM_read_PUBKEY failed"); return false; }
    *out = pkey;
    return true;
}

bool read_file_all(const std::string &path, std::vector<unsigned char> &out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { std::perror("open input"); return false; }
    in.seekg(0, std::ios::end);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size < 0) size = 0;
    out.resize(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(out.data()), size)) {
        std::perror("read input");
        return false;
    }
    return true;
}

bool write_file_all(const std::string &path, const std::vector<unsigned char> &data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) { std::perror("open output"); return false; }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) { std::perror("write output"); return false; }
    return true;
}

bool cmd_gen_key(const std::string &priv_path, const std::string &pub_path) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) { print_last_error("EVP_PKEY_CTX_new_id failed"); return false; }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        print_last_error("EVP_PKEY_keygen_init failed");
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        print_last_error("EVP_PKEY_keygen failed");
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    bool ok = write_private_key_pem(pkey, priv_path) && write_public_key_pem(pkey, pub_path);
    EVP_PKEY_free(pkey);
    return ok;
}

bool cmd_sign(const std::string &priv_path, const std::string &input_path, const std::string &sig_path) {
    EVP_PKEY *pkey = nullptr;
    if (!load_private_key(priv_path, &pkey)) return false;

    std::vector<unsigned char> msg;
    if (!read_file_all(input_path, msg)) { EVP_PKEY_free(pkey); return false; }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { print_last_error("EVP_MD_CTX_new failed"); EVP_PKEY_free(pkey); return false; }

    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        print_last_error("EVP_DigestSignInit failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, nullptr, &siglen, msg.data(), msg.size()) <= 0) {
        print_last_error("EVP_DigestSign (size) failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSign(mdctx, sig.data(), &siglen, msg.data(), msg.size()) <= 0) {
        print_last_error("EVP_DigestSign failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    sig.resize(siglen);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    if (!write_file_all(sig_path, sig)) return false;

    std::cout << "Signature written to: " << sig_path << " (" << sig.size() << " bytes)\n";
    return true;
}

bool cmd_verify(const std::string &pub_path, const std::string &input_path, const std::string &sig_path) {
    EVP_PKEY *pkey = nullptr;
    if (!load_public_key(pub_path, &pkey)) return false;

    std::vector<unsigned char> msg, sig;
    if (!read_file_all(input_path, msg)) { EVP_PKEY_free(pkey); return false; }
    if (!read_file_all(sig_path, sig)) { EVP_PKEY_free(pkey); return false; }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { print_last_error("EVP_MD_CTX_new failed"); EVP_PKEY_free(pkey); return false; }

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        print_last_error("EVP_DigestVerifyInit failed");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int rc = EVP_DigestVerify(mdctx, sig.data(), sig.size(), msg.data(), msg.size());

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    if (rc == 1) {
        std::cout << "OK: signature is valid." << std::endl;
        return true;
    } else if (rc == 0) {
        std::cout << "FAIL: signature is INVALID." << std::endl;
        return false;
    } else {
        print_last_error("EVP_DigestVerify failed");
        return false;
    }
}

void print_usage(const char* argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << " gen-key <private.pem> <public.pem>\n"
              << "  " << argv0 << " sign <private.pem> <input_file> <signature.sig>\n"
              << "  " << argv0 << " verify <public.pem> <input_file> <signature.sig>\n";
}

}

int main(int argc, char** argv) {
    openssl_init();

    if (argc < 2) { print_usage(argv[0]); openssl_cleanup(); return 1; }

    std::string cmd = argv[1];
    bool ok = false;

    if (cmd == "gen-key") {
        if (argc != 4) { print_usage(argv[0]); openssl_cleanup(); return 1; }
        ok = cmd_gen_key(argv[2], argv[3]);
    } else if (cmd == "sign") {
        if (argc != 5) { print_usage(argv[0]); openssl_cleanup(); return 1; }
        ok = cmd_sign(argv[2], argv[3], argv[4]);
    } else if (cmd == "verify") {
        if (argc != 5) { print_usage(argv[0]); openssl_cleanup(); return 1; }
        ok = cmd_verify(argv[2], argv[3], argv[4]);
    } else {
        print_usage(argv[0]);
    }

    openssl_cleanup();
    return ok ? 0 : 2;
}
