INIT_TIME = 1511884800
FINAL_TIME = 1604419200
MALWARE_SUBTYPE = ['WEBSHELL', 'DDOS木马', '被污染的基础软件', '恶意程序', '恶意脚本文件', '感染型病毒', '黑客工具', '后门程序', '勒索病毒', '漏洞利用程序',
                   '木马程序', '蠕虫病毒', '挖矿程序', '自变异木马']
ANPTHER_MALWARE_SUBTYPE = ['WEBSHELL', 'DDOS木马', '被污染的基础软件', '恶意程序', '恶意脚本文件', '感染型病毒', '黑客工具', '后门程序', '勒索病毒',
                           '漏洞利用程序',
                           '木马程序', '蠕虫病毒', '挖矿程序', '自变异木马']
REGION_LIST = ['cn-region-0', 'cn-region-1', 'cn-region-2', 'cn-region-3', 'cn-region-4', 'cn-region-5', 'cn-region-6',
               'cn-region-7', 'cn-region-8', 'cn-region-9', 'cn-region-10']

SENSITIVE_FUNC = ['eval', 'zend_compile_string', 'execute', 'exec', 'ex', '__construct', 'hextostr', 'hexdec',
                  'substr', 'strtr', 'base64_decode', 'define', 'kk', 's', 'vwff1', 'system', 'contentz',
                  'file_get_contents', 'loaddir', 'opendir', 'aishen', 'assert', 'a', 'gzinflate', 'b', 'base64_decode',
                  'call_user_func', 'preg_match', 'str_replace', 'Bar', 'create_function', 'filegetcontents',
                  'file_get_contents', 'file_put_contents',
                  'system', 'xxxx', 'dirtoarray', 'opendir', 'dd', '_con', 'file_get_contents', '_lon',
                  'download', 'file_exists', 'deldir', 'passthru', 'showdir', 'opendir', 'call_user_func_array',
                  'getvalue', 'call_user_func', 'mains', 'assert', 'test', 'l', 'getfile', 'file_get_contents',
                  'txt_to_file_ex', 'file_put_contents', 'pop']
