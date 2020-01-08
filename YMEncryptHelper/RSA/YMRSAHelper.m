//
//  YMRSAHelper.m
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/8.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "YMRSAHelper.h"
#import <Security/Security.h>

@implementation YMRSAHelper

+ (NSString *)RSAWithString:(NSString *)string
                  operation:(YMRSAHelperOperation)operation
                        key:(NSString *)key
                    keyType:(YMRSAHelperKeyType)keyType
{
    if (!string || ![string isKindOfClass:[NSString class]] || string.length == 0) {
        return nil;
    }
    
    NSData *inputData = nil;
    if (operation == YMRSAHelperOperationEncrypt) {
        inputData = [string dataUsingEncoding:NSUTF8StringEncoding];
    } else if (operation == YMRSAHelperOperationDecrypt) {
        inputData = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    }
    
    NSData *outputData = [self RSAWithData:inputData
                                 operation:operation
                                       key:key
                                   keyType:keyType];
    
    return [outputData base64EncodedStringWithOptions:0];
}

+ (NSData *)RSAWithData:(NSData *)data
              operation:(YMRSAHelperOperation)operation
                    key:(NSString *)key
                keyType:(YMRSAHelperKeyType)keyType
{
    if (!data || ![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    
    if (operation != YMRSAHelperOperationEncrypt &&
        operation != YMRSAHelperOperationDecrypt) {
        return nil;
    }
    
    if (!key || ![key isKindOfClass:[NSString class]] || key.length == 0) {
        return nil;
    }
    
    if (keyType != YMRSAHelperKeyTypePublic &&
        keyType != YMRSAHelperKeyTypePrivate) {
        return nil;
    }
    
    [self stripKey:key keyType:keyType];
    
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (keyType == YMRSAHelperKeyTypePublic) {
        keyData = [self stripPublicKeyHeader:keyData];
    } else {
        keyData = [self stripPrivateKeyHeader:keyData];
    }
    if (keyData.length == 0) {
        return nil;
    }
    
    NSMutableDictionary *options = [NSMutableDictionary dictionaryWithCapacity:3];
    options[(__bridge id)kSecAttrKeyType] = (__bridge id)kSecAttrKeyTypeRSA;
    options[(__bridge id)kSecAttrKeyClass] = (__bridge id)((keyType == YMRSAHelperKeyTypePublic) ? (kSecAttrKeyClassPublic) : (kSecAttrKeyClassPrivate));
    options[(__bridge id)kSecAttrKeySizeInBits] = @2048;
    NSError *error = nil;
    CFErrorRef errRef = (__bridge CFErrorRef)error;
    
    SecKeyRef keyRef = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)options, &errRef);
    if (errRef || !keyRef) {
        return nil;
    }
    
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void * outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    if (!outbuf) {
        return nil;
    }
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (size_t idx = 0; idx < srclen; idx += src_block_size) {
        size_t data_len = srclen - idx;
        if (data_len > src_block_size) {
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        
        if (keyType == YMRSAHelperKeyTypePrivate) {
            status = SecKeyRawSign(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen);
        } else {
            status = SecKeyEncrypt(keyRef,
                                   kSecPaddingPKCS1,
                                   srcbuf + idx,
                                   data_len,
                                   outbuf,
                                   &outlen);
        }
        
        if (status == noErr) {
            [ret appendBytes:outbuf length:outlen];
        } else {
            ret = nil;
            break;
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return [ret copy];
}

+ (void)stripKey:(NSString *)key keyType:(YMRSAHelperKeyType)keyType
{
    if (keyType == YMRSAHelperKeyTypePublic) {
        key = [key stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
        key = [key stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    } else {
        key = [key stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PRIVATE KEY-----" withString:@""];
        key = [key stringByReplacingOccurrencesOfString:@"-----END RSA PRIVATE KEY-----" withString:@""];
        key = [key stringByReplacingOccurrencesOfString:@"-----BEGIN PRIVATE KEY-----" withString:@""];
        key = [key stringByReplacingOccurrencesOfString:@"-----END PRIVATE KEY-----" withString:@""];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 private key header
    if (d_key == nil) return(nil);

    unsigned long len = [d_key length];
    if (!len) return(nil);

    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 22; //magic byte at offset 22

    if (0x04 != c_key[idx++]) return nil;

    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }

    // Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

@end
