//
//  YMAESHelper.h
//  TestThird
//
//  Created by yuman on 2020/1/7.
//  Copyright © 2020 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, YMAESHelperOperation) {
    YMAESHelperOperationEncrypt,
    YMAESHelperOperationDecrypt,
};

typedef NS_ENUM(NSInteger, YMAESHelperMode) {
    YMAESHelperModeECB,
    YMAESHelperModeCBC,
};

typedef NS_ENUM(NSInteger, YMAESHelperKeySize) {
    YMAESHelperKeySize128,
    YMAESHelperKeySize192,
    YMAESHelperKeySize256,
};

typedef NS_ENUM(NSInteger, YMAESHelperPadding) {
    YMAESHelperPaddingPKCS7,
};

@interface YMAESHelper : NSObject

/// 对NSString类型进行AES加密/解密。返回值为加解密后使用base64编码的string
/// 其余参数参看AESWithData:
+ (NSString *)AESWithString:(NSString *)string
                  operation:(YMAESHelperOperation)operation
                       mode:(YMAESHelperMode)mode
                    keySize:(YMAESHelperKeySize)keySize
                    padding:(YMAESHelperPadding)padding
                        key:(NSString *)key
                         iv:(NSString *)iv;

/// 对NSData类型进行AES加密/解密。返回值为加解密后的data，若失败则返回nil
/// @param data 欲加密/解密的data
/// @param operation 标记此次操作是加密还是解密
/// @param mode 标记AES算法的模式
/// @param keySize 标记AES算法使用的keySize(bits)
/// @param padding 标记AES算法使用的填充模式(目前iOS只提供了PKCS7)
/// @param key 密钥
/// @param iv 偏移量
+ (NSData *)AESWithData:(NSData *)data
              operation:(YMAESHelperOperation)operation
                   mode:(YMAESHelperMode)mode
                keySize:(YMAESHelperKeySize)keySize
                padding:(YMAESHelperPadding)padding
                    key:(NSString *)key
                     iv:(NSString *)iv;

@end
