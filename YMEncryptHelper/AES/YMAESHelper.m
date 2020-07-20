//
//  YMAESHelper.m
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/7.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "YMAESHelper.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation YMAESHelper

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
        mode != YMAESHelperModeCBC &&
        mode != YMAESHelperModeCFB &&
        mode != YMAESHelperModeCTR &&
        mode != YMAESHelperModeOFB) {
        return nil;
    }
    
    if (keySize != YMAESHelperKeySize128 &&
        keySize != YMAESHelperKeySize192 &&
        keySize != YMAESHelperKeySize256) {
        return nil;
    }
    
    if (padding != YMAESHelperPaddingNo &&
        padding != YMAESHelperPaddingPKCS7) {
        return nil;
    }
    
    if (!key || ![key isKindOfClass:[NSString class]] || key.length == 0) {
        return nil;
    }
    
    if (mode != YMAESHelperModeECB &&
        (!iv || ![iv isKindOfClass:[NSString class]] || iv.length == 0)) {
        return nil;
    }
    
    CCCryptorRef cryptorRef;
    CCOperation op = (operation == YMAESHelperOperationEncrypt) ? kCCEncrypt : kCCDecrypt;
    CCAlgorithm alg = kCCAlgorithmAES;
    CCMode ccmode = 0;
    size_t cckeySize = 0;
    CCPadding ccpadding = 0;
    
    switch (mode) {
        case YMAESHelperModeECB:
            ccmode = kCCModeECB;
            break;
        case YMAESHelperModeCBC:
            ccmode = kCCModeCBC;
            break;
        case YMAESHelperModeCFB:
            ccmode = kCCModeCFB;
            break;
        case YMAESHelperModeCTR:
            ccmode = kCCModeCTR;
            break;
        case YMAESHelperModeOFB:
            ccmode = kCCModeOFB;
            break;
    }
    
    switch (keySize) {
        case YMAESHelperKeySize128:
            cckeySize = kCCKeySizeAES128;
            break;
        case YMAESHelperKeySize192:
            cckeySize = kCCKeySizeAES192;
            break;
        case YMAESHelperKeySize256:
            cckeySize = kCCKeySizeAES256;
            break;
    }
    
    switch (padding) {
        case YMAESHelperPaddingNo:
            ccpadding = ccNoPadding;
            break;
        case YMAESHelperPaddingPKCS7:
            ccpadding = ccPKCS7Padding;
            break;
    }
    
    char keyPtr[cckeySize + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    memcpy(keyPtr, [key UTF8String], MIN(cckeySize, strlen([key UTF8String])));
    
    char ivPtr[cckeySize + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    if (mode != YMAESHelperModeECB) {
        memcpy(ivPtr, [iv UTF8String], MIN(cckeySize, strlen([iv UTF8String])));
    }
    
    CCCryptorStatus status = CCCryptorCreateWithMode(op,
                                                     ccmode,
                                                     alg,
                                                     ccpadding,
                                                     ivPtr,
                                                     keyPtr,
                                                     cckeySize,
                                                     NULL,
                                                     0,
                                                     0,
                                                     0,
                                                     &cryptorRef);
    
    if (status != kCCSuccess) {
        CCCryptorRelease(cryptorRef);
        return nil;
    }
    
    size_t bufsize = CCCryptorGetOutputLength(cryptorRef, (size_t)[data length], true);
    size_t bufused = 0;
    size_t bytesTotal = 0;
    void * buf = malloc(bufsize);
    if (!buf) {
        CCCryptorRelease(cryptorRef);
        return nil;
    }
    
    status = CCCryptorUpdate(cryptorRef, [data bytes], (size_t)[data length], buf, bufsize, &bufused);
    if (status != kCCSuccess) {
        free(buf);
        CCCryptorRelease(cryptorRef);
        return nil;
    }
    bytesTotal += bufused;
    
    status = CCCryptorFinal(cryptorRef, buf + bufused, bufsize - bufused, &bufused);
    if (status != kCCSuccess) {
        free(buf);
        CCCryptorRelease(cryptorRef);
        return nil;
    }
    bytesTotal += bufused;
    
    NSData *result = [NSData dataWithBytesNoCopy:buf length:bytesTotal];
    CCCryptorRelease(cryptorRef);
    
    return result;
}

@end
