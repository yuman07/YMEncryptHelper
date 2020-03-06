//
//  YMRSAHelper.h
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/8.
//  Copyright © 2020 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, YMRSAHelperOperation) {
    YMRSAHelperOperationEncrypt,
    YMRSAHelperOperationDecrypt,
};

typedef NS_ENUM(NSInteger, YMRSAHelperKeyType) {
    YMRSAHelperKeyTypePublic,
    YMRSAHelperKeyTypePrivate,
};

/// 需iOS >= 10
@interface YMRSAHelper : NSObject

/// 对NSData类型进行RSA加密/解密。返回值为加解密后的data，若失败则返回nil
/// @param data 欲加密/解密的data
/// @param operation 标记此次操作是加密还是解密
/// @param key 密钥
/// @param keyType 标记此密钥是公钥还是私钥
+ (NSData *)RSAWithData:(NSData *)data
              operation:(YMRSAHelperOperation)operation
                    key:(NSString *)key
                keyType:(YMRSAHelperKeyType)keyType;

@end
