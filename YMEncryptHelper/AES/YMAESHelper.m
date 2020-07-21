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
        padding != YMAESHelperPaddingZero &&
        padding != YMAESHelperPaddingPKCS5 &&
        padding != YMAESHelperPaddingPKCS7 &&
        padding != YMAESHelperPaddingANSIX923 &&
        padding != YMAESHelperPaddingISO10126) {
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
    CCMode ccmode = 0;
    size_t cckeySize = 0;
    
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
    
    if (operation == YMAESHelperOperationEncrypt) {
        data = [self addPaddingWithData:data padding:padding];
    }
    
    char keyPtr[cckeySize + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    memcpy(keyPtr, [key UTF8String], MIN(cckeySize, strlen([key UTF8String])));
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    if (mode != YMAESHelperModeECB) {
        memcpy(ivPtr, [iv UTF8String], MIN(kCCBlockSizeAES128, strlen([iv UTF8String])));
    }
    
    CCCryptorStatus status = CCCryptorCreateWithMode(op,
                                                     ccmode,
                                                     kCCAlgorithmAES,
                                                     ccNoPadding,
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
    bytesTotal += bufused;
    if (status != kCCSuccess || bytesTotal > bufsize) {
        free(buf);
        CCCryptorRelease(cryptorRef);
        return nil;
    }
    
    status = CCCryptorFinal(cryptorRef, buf + bufused, bufsize - bufused, &bufused);
    bytesTotal += bufused;
    if (status != kCCSuccess || bytesTotal > bufsize) {
        free(buf);
        CCCryptorRelease(cryptorRef);
        return nil;
    }
    
    NSData *result = [NSData dataWithBytesNoCopy:buf length:bytesTotal];
    CCCryptorRelease(cryptorRef);
    
    if (operation == YMAESHelperOperationDecrypt) {
        result = [self removePaddingWithData:result padding:padding];
    }
    
    return result;
}

+ (NSData *)addPaddingWithData:(NSData *)data padding:(YMAESHelperPadding)padding
{
    NSMutableData *result = [data mutableCopy];
    NSUInteger pad = 0;
    NSUInteger lengthNeedAdd = 16 - data.length % 16;
    
    switch (padding) {
        case YMAESHelperPaddingNo: {
            return data;
        }
        case YMAESHelperPaddingZero: {
            for (NSUInteger i = 0; i < lengthNeedAdd; i++) {
                [result appendBytes:&pad length:1];
            }
            return [result copy];
        }
        case YMAESHelperPaddingPKCS5:
        case YMAESHelperPaddingPKCS7: {
            for (NSUInteger i = 0; i < lengthNeedAdd; i++) {
                [result appendBytes:&lengthNeedAdd length:1];
            }
            return [result copy];
        }
        case YMAESHelperPaddingANSIX923: {
            for (NSUInteger i = 0; i < lengthNeedAdd - 1; i++) {
                [result appendBytes:&pad length:1];
            }
            [result appendBytes:&lengthNeedAdd length:1];
            return [result copy];
            
        }
        case YMAESHelperPaddingISO10126: {
            for (NSUInteger i = 0; i < lengthNeedAdd - 1; i++) {
                pad = arc4random() % 256;
                [result appendBytes:&pad length:1];
            }
            [result appendBytes:&lengthNeedAdd length:1];
            return [result copy];
        }
    }
}

+ (NSData *)removePaddingWithData:(NSData *)data padding:(YMAESHelperPadding)padding
{
    Byte *bytes = (Byte *)data.bytes;
    NSUInteger count = 0;
    
    switch (padding) {
        case YMAESHelperPaddingNo: {
            return data;
        }
        case YMAESHelperPaddingZero: {
            for (NSInteger i = data.length - 1; i >= 0; i--) {
                if (bytes[i] != 0) {
                    count = data.length - 1 - i;
                    break;
                }
            }
            NSUInteger length = data.length - count;
            if (length > data.length) {
                return nil;
            }
            return [data subdataWithRange:NSMakeRange(0, length)];
        }
        case YMAESHelperPaddingPKCS5:
        case YMAESHelperPaddingPKCS7:
        case YMAESHelperPaddingANSIX923:
        case YMAESHelperPaddingISO10126: {
            if (data.length < 1) {
                return nil;
            }
            count = bytes[data.length - 1];
            NSUInteger length = data.length - count;
            if (length > data.length) {
                return nil;
            }
            return [data subdataWithRange:NSMakeRange(0, length)];
        }
    }
}

@end
