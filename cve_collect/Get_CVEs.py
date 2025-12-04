import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlencode
import time
import json
from collections import OrderedDict
import os

def output(path, content):
    file = path
    with open(file, 'w', encoding="utf-8") as f:
        f.write(content)

# serch for repositories on GitHub
def search_github():
    page = 1
    repositories = []
    while(1):
        baseurl = "https://api.github.com/search/repositories?"
        params = {
            "q": "stars:1000...2300 language:python",
            "sort": "stars",
            "order": "desc",
            "per_page": "100",
            "page": str(page)
        }
        url = baseurl + urlencode(params)
        print(url)
        headers = {'User-Agent':'Mozilla/5.0',
           'Authorization': 'Bearer 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',
           'Accept':'application/vnd.github+json'
        }
        
        response = requests.get(url, headers=headers)
        #output(path, response.text, str(page))
        
        if response.status_code != 200:
            print("GitHub数据获取错误")
            break
        
        json_data = json.loads(response.text)
        for item in json_data['items']:
            repositories.append(item["full_name"])

    
        page += 1
        
        time.sleep(2)
        
    return repositories

def filter_same_repository(repo_name, cve_tags_sub):
    cve_list = []
    #print(cve_tags_sub)
    
    for tag_sub in cve_tags_sub[0:200]:
        
        '''
        cve_id = tag_sub.text.strip()
        if cve_id.startswith("CVE-"):
            cve_list.append(cve_id)
        '''
        
        cve_id = tag_sub.text.strip()
        #print(cve_id)
        
        detail_baseurl = f"https://cve.mitre.org/cgi-bin/cvename.cgi?"
        detail_params = {
            "name": cve_id
        }
        detail_url = detail_baseurl + urlencode(detail_params)
        
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(detail_url, headers=headers)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        #print(response.text)
        #print("------------------------------------------")
        # ensure its CVE of this project
        cve_tags = soup.find_all('a', href=re.compile(r"{}".format(repo_name), re.IGNORECASE))
        #print(cve_tags)
        if len(cve_tags) != 0:
            cve_list.append(cve_id)

# return CVE list got by searching from CVE website
# return: cvelist
def search_cve_for_repo(repo_name, keywords):

    search_baseurl = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?"
    search_params = {
        "keyword": repo_name + ' ' + keywords
    }
    search_url = search_baseurl + urlencode(search_params)
    
    headers = {"User-Agent": "Mozilla/5.0"}
    
    response_sub = requests.get(search_url, headers=headers)
    #print(response.text)
    
    if response_sub.status_code != 200:
        print(f"CVE MITRE Searching Failed: {repo_name}")
        return []
    
    soup_sub = BeautifulSoup(response_sub.text, 'html.parser')
    
    
    
    # 找到所有指向CVE详情的链接，链接格式通常为 /cgi-bin/cvename.cgi?name=CVE-XXXX-XXXX
    # cve_tags_sub = soup_sub.find_all('a', href=re.compile(r'https://www.cve.org/CVERecord\?id=CVE-'))
    # cve_list = [cve.text.strip() for cve in cve_tags_sub]
    
    cve_list = []
    
    table = soup_sub.find_all('table')[2]
    
    for row in table.find_all('tr'):
        content = row.find_all('td')
        if len(content) != 0:
            cve_id = content[0].text
            description = content[1].text
            
            # is repo_name exist in description?
            if re.match(rf'.*{repo_name}.*', description, re.I|re.M):
                cve_list.append(cve_id)
                #print(f"{cve_id}:{description}")
        
    return cve_list

# 在 NVD 上获取 CVE 的 CWE 类型信息
# return: cwelist
def get_cwe_from_nvd(cve_id):
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    headers = {"User-Agent": "Mozilla/5.0"}
    
    
    #response = requests.get(nvd_url, headers=headers)
    
    #重试几次
    response = None
    i = 0
    while i < 3:
        try:
            response = requests.get(nvd_url, headers=headers, timeout=60)
            break
        except requests.exceptions.RequestException:
            i += 1
    
    
    if response.status_code != 200:
        print(f"NVD查询失败: {cve_id}")
        return None
    
    #print(response.text)
    
    soup = BeautifulSoup(response.text, 'html.parser')
    # NVD页面中，CWE信息通常作为一个链接，href包含'/cwe/'的链接
    cwe_links = soup.find_all('a', href=re.compile(r'http://cwe.mitre.org/data/definitions/'))
    #print(cwe_links)
    if len(cwe_links) != 0:
        return [cwe_link.text.strip() for cwe_link in cwe_links]
    return None

# 判断CVE的CWE类型是否属于目标漏洞类型
def is_target_vulnerability(cve_id, target_types):
    cwe_list = get_cwe_from_nvd(cve_id)
    
    if cwe_list == None:
        return False
    
    for cwe in cwe_list:
        # 简单匹配目标漏洞类型关键词（不区分大小写）
        if cwe in target_types:
            return True
    return False

def main():
    
    path = "./repositories2300.txt"
    
    out_dic = "repo_cves2300"
    
    
    repositories = []
    with open(path, 'r', encoding='utf-8') as f:
        repositories = f.readlines()
        repositories = [i.strip() for i in repositories]   
    
    
    # 定义目标漏洞类型关键词
    target_vuln_types = [
        "CWE-79",
        "CWE-22",
        "CWE-89",
        "CWE-77",
        "CWE-78",
        "CWE-502",
        "CWE-94"
    ]
    
    STEP = 20
    index = 0
    
    while(index < len(repositories)):
        try:
            print(f"正在处理batch: {index} 至 {index + STEP - 1}")
            
            # 检查是否已经处理过
            if os.path.exists(f"./{out_dic}/{index}.json"):
                index += STEP
                continue
            
            batch_repositories = repositories[index:index+STEP]
            repo_cves = OrderedDict()
            
            # 对每个仓库搜索相关的 CVE
            for repo in batch_repositories:
                repo_cves[repo] = []
                print(f"正在处理仓库：{repo}")
                cve_list = search_cve_for_repo(repo)
                # 为避免请求过快，适当延时
                time.sleep(1)
                for cve in cve_list:
                    # 对每个CVE，检查其CWE信息
                    if is_target_vulnerability(cve, target_vuln_types):
                        repo_cves[repo].append(cve)
                    # 延时，避免频繁请求NVD
                    time.sleep(1)
            json_str = json.dumps(repo_cves)
            output(f"./{out_dic}/{index}.json", json_str)
            index += STEP
        except:
            continue

if __name__ == '__main__':
    main()
    
    