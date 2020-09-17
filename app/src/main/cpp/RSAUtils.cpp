//
// Created by Simp1er on 2020-09-16.
//  reference from https://fucknmb.com/2017/04/09/Android%E5%9C%A8NDK%E5%B1%82%E4%BD%BF%E7%94%A8OpenSSL%E8%BF%9B%E8%A1%8CRSA%E5%8A%A0%E5%AF%86/
//
/**
 * 注：openssl 中
 *     公钥加密 = 加密
 *     私钥解密 = 解密
 *     私钥加密 = 签名
 *     公钥解密 = 验证
*/
/**
 * 根据公钥base64字符串（没换行）生成公钥文本内容
 * @param base64EncodedKey
 * @return
 */

#include "RSAUtils.h"
using std::string;
std::string generatePublicKey(std::string base64EncodedKey) {
    std::string publicKey = base64EncodedKey;
    size_t base64Length = 76;//每64个字符一行
    size_t publicKeyLength = base64EncodedKey.size();
    for (size_t i = base64Length; i < publicKeyLength; i += base64Length) {
        //每base64Length个字符，增加一个换行
        if (base64EncodedKey[i] != '\n') {
            publicKey.insert(i, "\n");
        }
        i++;
    }
    //最前面追加公钥begin字符串
    publicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    //最前面追加公钥end字符串
    publicKey.append("\n-----END PUBLIC KEY-----");
    return publicKey;
}
/**
 * base64 encode
 * @param decoded_bytes
 * @return
 */
std::string base64_encode(const std::string &decoded_bytes) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    //不换行
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    //encode
    BIO_write(bio, decoded_bytes.c_str(), (int) decoded_bytes.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    //这里的第二个参数很重要，必须赋值
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}
/**
 * 使用公钥对明文加密
 * @param publicKey
 * @param from
 * @return
 */
std::string encryptRSA(const std::string &publicKey, const std::string &from) {
    BIO *bio = NULL;
    RSA *rsa_public_key = NULL;

    //从字符串读取RSA公钥串
    if ((bio = BIO_new_mem_buf((void *) publicKey.c_str(), -1)) == NULL) {
        std::cout << "BIO_new_mem_buf failed!" << std::endl;
        return "";
    }
    //读取公钥
    rsa_public_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    //异常处理
    if (rsa_public_key == NULL) {
        //资源释放
        BIO_free_all(bio);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }

    //rsa模的位数
    int rsa_size = RSA_size(rsa_public_key);

    //RSA_PKCS1_PADDING 最大加密长度 为 128 -11
    //RSA_NO_PADDING 最大加密长度为  128
    //rsa_size = rsa_size - RSA_PKCS1_PADDING_SIZE;

    //动态分配内存，用于存储加密后的密文
    unsigned char *to = (unsigned char *) malloc(rsa_size + 1);
    //填充0
    memset(to, 0, rsa_size + 1);

    //明文长度
    int flen = from.length();

    //加密，返回值为加密后的密文长度，-1表示失败
    int status = RSA_public_encrypt(flen, (const unsigned char *) from.c_str(), to, rsa_public_key,
                                    RSA_PKCS1_PADDING);
    //异常处理
    if (status < 0) {
        //资源释放
        free(to);
        BIO_free_all(bio);
        RSA_free(rsa_public_key);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }

    //赋值密文
    static std::string result((char *) to, status);

    //资源释放
    free(to);
    BIO_free_all(bio);
    RSA_free(rsa_public_key);
    //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
    CRYPTO_cleanup_all_ex_data();
    return result;
}
/**
 * base64 decode
 * @param encoded_bytes
 * @return
 */
std::string base64_decode(const std::string &encoded_bytes) {
    BIO *bioMem, *b64;

    bioMem = BIO_new_mem_buf((void *) encoded_bytes.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bioMem = BIO_push(b64, bioMem);

    //获得解码长度
    size_t buffer_length = BIO_get_mem_data(bioMem, NULL);

    char *decode = (char *) malloc(buffer_length + 1);
    //填充0
    memset(decode, 0, buffer_length + 1);

    BIO_read(bioMem, (void *) decode, (int) buffer_length);

    static std::string decoded_bytes(decode);

    BIO_free_all(bioMem);

    return decoded_bytes;
}
/**
 * 根据私钥base64字符串（没换行）生成私钥文本内容
 * @param base64EncodedKey
 * @return
 */
std::string generatePrivateKey(std::string base64EncodedKey) {
    std::string privateKey = base64EncodedKey;
    size_t base64Length = 64;//每64个字符一行
    size_t privateKeyLength = base64EncodedKey.size();
    for (size_t i = base64Length; i < privateKeyLength; i += base64Length) {
        //每base64Length个字符，增加一个换行
        if (base64EncodedKey[i] != '\n') {
            privateKey.insert(i, "\n");
        }
        i++;
    }
    //最前面追加私钥begin字符串
    privateKey.insert(0, "-----BEGIN PRIVATE KEY-----\n");
    //最后面追加私钥end字符串
    privateKey.append("\n-----END PRIVATE KEY-----");
    return privateKey;
}
/**
 * 使用私钥对密文解密
 * @param privetaKey
 * @param from
 * @return
 */
std::string decryptRSA(const std::string &privetaKey, const std::string &from) {
    BIO *bio = NULL;
    RSA *rsa_private_key = NULL;
    //从字符串读取RSA公钥串
    if ((bio = BIO_new_mem_buf((void *) privetaKey.c_str(), -1)) == NULL) {
        std::cout << "BIO_new_mem_buf failed!" << std::endl;
        return "";
    }
    //读取私钥
    rsa_private_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    //异常处理
    if (rsa_private_key == NULL) {
        //资源释放
        BIO_free_all(bio);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }

    //rsa模的位数
    int rsa_size = RSA_size(rsa_private_key);

    //动态分配内存，用于存储解密后的明文
    unsigned char *to = (unsigned char *) malloc(rsa_size + 1);
    //填充0
    memset(to, 0, rsa_size + 1);

    //密文长度
    int flen = from.length();

    // RSA_NO_PADDING
    // RSA_PKCS1_PADDING
    //解密，返回值为解密后的名文长度，-1表示失败
    int status = RSA_private_decrypt(flen, (const unsigned char *) from.c_str(), to, rsa_private_key,
                                     RSA_PKCS1_PADDING);
    //异常处理率
    if (status < 0) {
        //释放资源
        free(to);
        BIO_free_all(bio);
        RSA_free(rsa_private_key);
        //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
        CRYPTO_cleanup_all_ex_data();
        return "";
    }

    //赋值明文，是否需要指定to的长度？
    static std::string result((char *) to);

    //释放资源
    free(to);
    BIO_free_all(bio);
    RSA_free(rsa_private_key);
    //清除管理CRYPTO_EX_DATA的全局hash表中的数据，避免内存泄漏
    CRYPTO_cleanup_all_ex_data();
    return result;
}


