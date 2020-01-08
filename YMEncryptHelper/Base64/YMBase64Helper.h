//
//  YMBase64Helper.h
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/8.
//  Copyright © 2020 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface YMBase64Helper : NSObject

/// base64编码：data -> string
+ (NSString *)base64EncodeWithData:(NSData *)data;

/// base64解码：string -> data
+ (NSData *)base64DecodeWithString:(NSString *)string;

@end
