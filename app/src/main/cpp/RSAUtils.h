//
// Created by Simp1er on 2020-09-16.
// // reference from https://fucknmb.com/2017/04/09/Android%E5%9C%A8NDK%E5%B1%82%E4%BD%BF%E7%94%A8OpenSSL%E8%BF%9B%E8%A1%8CRSA%E5%8A%A0%E5%AF%86/
//

#ifndef RSA_RSAUTILS_H
#define RSA_RSAUTILS_H
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <iostream>
using std::string;

std::string generatePublicKey(std::string base64EncodedKey);
std::string base64_encode(const std::string &decoded_bytes);
std::string encryptRSA(const std::string &publicKey, const std::string &from);
std::string decryptRSA(const std::string &privetaKey, const std::string &from);
std::string base64_decode(const std::string &encoded_bytes);
#endif //RSA_RSAUTILS_H
