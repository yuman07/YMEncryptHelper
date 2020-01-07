//
//  YMAESHelper.m
//  TestThird
//
//  Created by yuman on 2020/1/7.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "YMAESHelper.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation YMAESHelper

+ (NSString *)AESWorkWithType:(YMAESHelperType)type
                    algorithm:(YMAESHelperAlgorithm)algorithm
                       string:(NSString *)string
                         mode:(YMAESHelperMode)mode
                      padding:(YMAESHelperPadding)padding
                          key:(NSString *)key
                           iv:(NSString *)iv
{
    if (!string || ![string isKindOfClass:[NSString class]] || string.length == 0) {
        return nil;
    }
    
    NSData *inputData = nil;
    if (type == YMAESHelperTypeEncrypt) {
        inputData = [string dataUsingEncoding:NSUTF8StringEncoding];
    } else if (type == YMAESHelperTypeDecrypt) {
        inputData = [[NSData alloc] initWithBase64EncodedString:string options:0];
    }
    NSData *data = [self AESWorkWithType:type
                               algorithm:algorithm
                                    data:inputData
                                    mode:mode
                                 padding:YMAESHelperPaddingPKCS7
                                     key:key
                                      iv:iv];
    return [data base64EncodedStringWithOptions:0];
}

+ (NSData *)AESWorkWithType:(YMAESHelperType)type
                  algorithm:(YMAESHelperAlgorithm)algorithm
                       data:(NSData *)data
                       mode:(YMAESHelperMode)mode
                    padding:(YMAESHelperPadding)padding
                        key:(NSString *)key
                         iv:(NSString *)iv
{
    if (type != YMAESHelperTypeEncrypt &&
        type != YMAESHelperTypeDecrypt) {
        return nil;
    }
    
    if (algorithm != YMAESHelperAlgorithmAES128 &&
        algorithm != YMAESHelperAlgorithmAES192 &&
        algorithm != YMAESHelperAlgorithmAES256) {
        return nil;
    }
    
    if (!data || ![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    
    if (mode != YMAESHelperModeCBC &&
        mode != YMAESHelperModeECB) {
        return nil;
    }
    
    if (padding != YMAESHelperPaddingPKCS7) {
        return nil;
    }
    
    if (!key || ![key isKindOfClass:[NSString class]] || key.length == 0) {
        return nil;
    }
    
    if (mode != YMAESHelperModeECB &&
        (!iv || ![iv isKindOfClass:[NSString class]] || iv.length == 0)) {
        return nil;
    }
    
    CCOperation op = (type == YMAESHelperTypeEncrypt) ? kCCEncrypt : kCCDecrypt;
    CCAlgorithm alg = kCCAlgorithmAES;
    CCOptions options = 0;
    if (mode == YMAESHelperModeECB) {
        options |= kCCOptionECBMode;
    }
    if (padding == YMAESHelperPaddingPKCS7) {
        options |= kCCOptionPKCS7Padding;
    }
    
    size_t keySize = 0;
    size_t blockSize = kCCBlockSizeAES128;
    if (algorithm == YMAESHelperAlgorithmAES128) {
        keySize = kCCKeySizeAES128;
    } else if (algorithm == YMAESHelperAlgorithmAES192) {
        keySize = kCCKeySizeAES192;
    } else {
        keySize = kCCKeySizeAES256;
    }
    
    char keyPtr[keySize + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    memcpy(keyPtr, [key UTF8String], MIN(keySize, strlen([key UTF8String])));
    
    char ivPtr[blockSize + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    if (mode != YMAESHelperModeECB && iv) {
        memcpy(ivPtr, [iv UTF8String], MIN(blockSize, strlen([iv UTF8String])));
    }
    
    size_t bufferSize = data.length + blockSize;
    size_t bufferLength = 0;
    void * buffer = malloc(bufferSize);
    if (!buffer) {
        return nil;
    }
    
    CCCryptorStatus cryptStatus = CCCrypt(op,
                                          alg,
                                          options,
                                          keyPtr,
                                          keySize,
                                          ivPtr,
                                          data.bytes,
                                          data.length,
                                          buffer,
                                          bufferSize,
                                          &bufferLength);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:bufferLength];
    }
    
    free(buffer);
    return nil;
}

@end
