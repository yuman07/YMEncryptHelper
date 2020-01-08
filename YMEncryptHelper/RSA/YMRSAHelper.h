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

@interface YMRSAHelper : NSObject

- (NSData *)RSAWithData:(NSData *)data
              operation:(YMRSAHelperOperation)operation
                    key:(NSString *)key
                keyType:(YMRSAHelperKeyType)keyType;

@end
