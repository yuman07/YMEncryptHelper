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

+ (NSString *)AESWithString:(NSString *)string
                  operation:(YMAESHelperOperation)operation
                       mode:(YMAESHelperMode)mode
                    keySize:(YMAESHelperKeySize)keySize
                    padding:(YMAESHelperPadding)padding
                        key:(NSString *)key
                         iv:(NSString *)iv
{
    if (!string || ![string isKindOfClass:[NSString class]] || string.length == 0) {
        return nil;
    }
    
    NSData *inputData = nil;
    if (operation == YMAESHelperOperationEncrypt) {
        inputData = [string dataUsingEncoding:NSUTF8StringEncoding];
    } else if (operation == YMAESHelperOperationDecrypt) {
        inputData = [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
    }
    
    NSData *outputData = [self AESWithData:inputData
                                 operation:operation
                                      mode:mode
                                   keySize:keySize
                                   padding:padding
                                       key:key
                                        iv:iv];
    
    return [outputData base64EncodedStringWithOptions:0];
}

+ (NSData *)AESWithData:(NSData *)data
              operation:(YMAESHelperOperation)operation
                   mode:(YMAESHelperMode)mode
                keySize:(YMAESHelperKeySize)keySize
                padding:(YMAESHelperPadding)padding
                    key:(NSString *)key
                     iv:(NSString *)iv
{
    if (!data || ![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    
    if (operation != YMAESHelperOperationEncrypt &&
        operation != YMAESHelperOperationDecrypt) {
        return nil;
    }
    
    if (mode != YMAESHelperModeECB &&
        mode != YMAESHelperModeCBC) {
        return nil;
    }
    
    if (keySize != YMAESHelperKeySize128 &&
        keySize != YMAESHelperKeySize192 &&
        keySize != YMAESHelperKeySize256) {
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
    
    CCOperation op = (operation == YMAESHelperOperationEncrypt) ? kCCEncrypt : kCCDecrypt;
    CCAlgorithm alg = kCCAlgorithmAES;
    CCOptions options = 0;
    if (mode == YMAESHelperModeECB) {
        options |= kCCOptionECBMode;
    }
    if (padding == YMAESHelperPaddingPKCS7) {
        options |= kCCOptionPKCS7Padding;
    }
    
    size_t keyLength = 0;
    size_t blockLength = kCCBlockSizeAES128;
    if (keySize == YMAESHelperKeySize128) {
        keyLength = kCCKeySizeAES128;
    } else if (keySize == YMAESHelperKeySize192) {
        keyLength = kCCKeySizeAES192;
    } else {
        keyLength = kCCKeySizeAES256;
    }
    
    char keyPtr[keyLength + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    memcpy(keyPtr, [key UTF8String], MIN(keyLength, strlen([key UTF8String])));
    
    char ivPtr[blockLength + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    if (mode != YMAESHelperModeECB) {
        memcpy(ivPtr, [iv UTF8String], MIN(blockLength, strlen([iv UTF8String])));
    }
    
    size_t bufferSize = data.length + blockLength;
    size_t bufferLength = 0;
    void * buffer = malloc(bufferSize);
    if (!buffer) {
        return nil;
    }
    
    CCCryptorStatus status = CCCrypt(op,
                                     alg,
                                     options,
                                     keyPtr,
                                     keyLength,
                                     ivPtr,
                                     data.bytes,
                                     data.length,
                                     buffer,
                                     bufferSize,
                                     &bufferLength);
    
    if (status == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:bufferLength];
    }
    
    free(buffer);
    return nil;
}

@end
