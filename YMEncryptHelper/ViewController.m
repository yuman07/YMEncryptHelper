//
//  ViewController.m
//  YMEncryptHelper
//
//  Created by yuman on 2020/1/7.
//  Copyright © 2020 yuman. All rights reserved.
//

#import "ViewController.h"
#import "YMAESHelper.h"

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
    NSString *string1 = [YMAESHelper AESWorkWithString:@"你好123"
                                             operation:YMAESHelperOperationEncrypt
                                                  mode:YMAESHelperModeCBC
                                               keySize:YMAESHelperKeySize192
                                               padding:YMAESHelperPaddingPKCS7
                                                   key:@"111"
                                                    iv:@"111"];
    
    NSString *string2 = [YMAESHelper AESWorkWithString:@"o9fmlIDGsH+bAn8zKaf2hw=="
                                             operation:YMAESHelperOperationDecrypt
                                                  mode:YMAESHelperModeCBC
                                               keySize:YMAESHelperKeySize128
                                               padding:YMAESHelperPaddingPKCS7
                                                   key:@"111"
                                                    iv:@"111"];
    
    NSLog(@"%@", string1);
    NSLog(@"%@", string2);
}

- (void)testRSA
{
    
}


@end
