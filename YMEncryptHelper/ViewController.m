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
    NSString *string = [YMAESHelper AESWorkWithType:YMAESHelperTypeEncrypt
                                          algorithm:YMAESHelperAlgorithmAES128
                                             string:@"你好123你好123你好123你好123"
                                               mode:YMAESHelperModeCBC
                                            padding:YMAESHelperPaddingPKCS7
                                                key:@"你好"
                                                 iv:@"你好"];
    
    NSString *result = [YMAESHelper AESWorkWithType:YMAESHelperTypeDecrypt
                                          algorithm:YMAESHelperAlgorithmAES128
                                             string:@"lC8XYtW8/zepkriUgg1Kt1WbH1c3wlflkDAFjQ0kcII4tLCi7pgS1342Tg5lz4p0"
                                               mode:YMAESHelperModeCBC
                                            padding:YMAESHelperPaddingPKCS7
                                                key:@"你好"
                                                 iv:@"你好"];
    
    NSLog(@"%@", string);
    NSLog(@"%@", result);
}

- (void)testRSA
{
    
}


@end
