//
//  YMAESHelper.h
//  TestThird
//
//  Created by yuman on 2020/1/7.
//  Copyright © 2020 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, YMAESHelperType) {
    YMAESHelperTypeEncrypt,
    YMAESHelperTypeDecrypt,
};

typedef NS_ENUM(NSInteger, YMAESHelperAlgorithm) {
    YMAESHelperAlgorithmAES128,
    YMAESHelperAlgorithmAES192,
    YMAESHelperAlgorithmAES256,
};

typedef NS_ENUM(NSInteger, YMAESHelperMode) {
    YMAESHelperModeCBC,
    YMAESHelperModeECB,
};

typedef NS_ENUM(NSInteger, YMAESHelperPadding) {
    YMAESHelperPaddingPKCS7,
};

@interface YMAESHelper : NSObject

/// 对于NSString类型，使用AES算法加密/解密。返回值为加解密后的string(加密使用base64编码)，若失败则返回nil
/// @param type 标记是加密还是解密
/// @param algorithm 标记使用哪种AES算法
/// @param string 欲加/解密的string(欲解密的string需使用base64编码)
/// @param mode 标记使用AES算法的哪种模式
/// @param padding 标记填充模式(目前iOS只支持PKCS7Padding)
/// @param key 密钥
/// @param iv 偏移量(对于非ECB模式需要)
+ (NSString *)AESWorkWithType:(YMAESHelperType)type
                    algorithm:(YMAESHelperAlgorithm)algorithm
                       string:(NSString *)string
                         mode:(YMAESHelperMode)mode
                      padding:(YMAESHelperPadding)padding
                          key:(NSString *)key
                           iv:(NSString *)iv;

/// 对NSData类型，使用AES算法加密/解密。返回值为加解密后的data，若失败则返回nil
/// @param type 标记是加密还是解密
/// @param algorithm 标记使用哪种AES算法
/// @param data 欲加/解密的数据
/// @param mode 标记使用AES算法的哪种模式
/// @param padding 标记填充模式(目前iOS只支持PKCS7Padding)
/// @param key 密钥
/// @param iv 偏移量(对于非ECB模式需要)
+ (NSData *)AESWorkWithType:(YMAESHelperType)type
                  algorithm:(YMAESHelperAlgorithm)algorithm
                       data:(NSData *)data
                       mode:(YMAESHelperMode)mode
                    padding:(YMAESHelperPadding)padding
                        key:(NSString *)key
                         iv:(NSString *)iv;

@end
