//
//  YMRSAHelper.m
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/8.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "YMRSAHelper.h"

@implementation YMRSAHelper

- (NSData *)RSAWithData:(NSData *)data
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
    
    
    return nil;
}

@end
