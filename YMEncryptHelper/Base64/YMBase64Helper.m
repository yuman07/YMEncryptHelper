//
//  YMBase64Helper.m
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/8.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "YMBase64Helper.h"

@implementation YMBase64Helper

+ (NSString *)base64EncodeWithData:(NSData *)data
{
    if (!data || ![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    return [data base64EncodedStringWithOptions:0];
}

+ (NSData *)base64DecodeWithString:(NSString *)string
{
    if (!string || ![string isKindOfClass:[NSString class]] || string.length == 0) {
        return nil;
    }
    return [[NSData alloc] initWithBase64EncodedString:string options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

@end
