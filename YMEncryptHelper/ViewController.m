//
//  ViewController.m
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/7.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "ViewController.h"
#import "YMAESHelper.h"
#import "YMRSAHelper.h"
#import "YMBase64Helper.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.

    [self testAES];
    
//    [self testRSA];
    
}

- (void)testAES
{
    NSString *key = @"111";
    NSString *iv = @"222";
    
    NSData *data1 = [YMAESHelper AESWithData:[@"你好123" dataUsingEncoding:NSUTF8StringEncoding]
                                   operation:YMAESHelperOperationEncrypt
                                        mode:YMAESHelperModeOFB
                                     keySize:YMAESHelperKeySize128
                                     padding:YMAESHelperPaddingANSIX923
                                         key:key
                                          iv:iv];
    
    NSData *data2 = [YMAESHelper AESWithData:data1
                                   operation:YMAESHelperOperationDecrypt
                                        mode:YMAESHelperModeOFB
                                     keySize:YMAESHelperKeySize128
                                     padding:YMAESHelperPaddingANSIX923
                                         key:key
                                          iv:iv];
    
    NSLog(@"%@", [YMBase64Helper base64EncodeWithData:data1]);
    NSLog(@"%@", [[NSString alloc] initWithData:data2 encoding:NSUTF8StringEncoding]);
}

- (void)testRSA
{
    NSString *publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPlM9x9Uth5KNjrjdJfpN8hygyoPHBQMwB8ngiO0VCj/xsLksyTmO7rhuLhGK4XuGNgL3mqL0jz7UfDwdGG86Y1V5Cef4Ii/4/N1JsP5KC+S5VLZKb+fIILJ0dyP7eTJTZ/mJpkWDzPoGFeqET0mg50LmrUyBYI2uYBBzIxmbH9wIDAQAB";
    NSString *privateKey = @"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAI+Uz3H1S2Hko2OuN0l+k3yHKDKg8cFAzAHyeCI7RUKP/GwuSzJOY7uuG4uEYrhe4Y2AveaovSPPtR8PB0YbzpjVXkJ5/giL/j83Umw/koL5LlUtkpv58ggsnR3I/t5MlNn+YmmRYPM+gYV6oRPSaDnQuatTIFgja5gEHMjGZsf3AgMBAAECgYAjVFyPD+qSle3WU0HrZafo1mD/xDZ4dPc962nAEpGCRWe5PtLl9//2aGsCs3qPH1mkte8EWLThoPRSRiJmD+WPuUi5xGI6r8FFzeM+4bVAMVrKBWFHAMgph7t39aXb2zIiQZ5scAFWR7MD/6InryjuVhh5+x7L4oaa1KfBJACdkQJBAOzgwnDfLLtrambFzyKu1FuFyfC7yA2WYy/EeTxg+OMppoy+7No7er0bd8OM/0Cp7+QIBJP2QEImCB67VhqYc2MCQQCbLANV/L4AdAJTX81jsJDzp0inwKDmbxotsZA+SuC6UV18GvYe2Gi1kzTyo5G9En9oMDy9cAXC8VbyxRUjur9dAkBgxqbJ5HPrEkSDPneUzOaXib5qKt3dpz5YqqV5ZIjqjf6sa+hqdHh9wDYa34T9TzBh8mCkbqvsGougupq//N7PAkEAkb3K/E5AXsiXDpvimwlRe6fY88ZW2VfsrJIjun41iIm3VkM0e1AjOLekeWjsDzt6cu8rfXnjz29BjQ9ShZZ2+QJBAMobBdzBUkb1is6oXzhRA641SUzeFGwTgHApaozhmuNN1F5at++2WczN1JijDldD7z/bsN44uD4qpHEAHtTLFt0=";
    
    NSData *data1 = [YMRSAHelper RSAWithData:[@"你好123" dataUsingEncoding:NSUTF8StringEncoding]
                                   operation:YMRSAHelperOperationEncrypt
                                         key:privateKey
                                     keyType:YMRSAHelperKeyTypePrivate];
    
    NSData *data2 = [YMRSAHelper RSAWithData:data1
                                   operation:YMRSAHelperOperationDecrypt
                                         key:publicKey
                                     keyType:YMRSAHelperKeyTypePublic];
    
    NSLog(@"%@", [YMBase64Helper base64EncodeWithData:data1]);
    NSLog(@"%@", [[NSString alloc] initWithData:data2 encoding:NSUTF8StringEncoding]);
}

@end
