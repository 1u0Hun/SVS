# !/usr/bin/env python
#encoding: utf-8
# @Author  : Hakuna
# @Site    : QVQ
# @File    : awvs_api_11.py.py
# @Software: PyCharm

import json
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
'''
import requests.packages.urllib3.util.ssl_
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'
or
pip install requests[security]
'''
class wvs():

    def __init__(self):
        self.tarurl = "https://127.0.0.1:3443/"
        self.apikey = "1986ad8c0a5b3df4d7028d5f3c06e936cf724472331214b5c8f4a281e83b5b4bc"
        self.headers = {"X-Auth": self.apikey, "content-type": "application/json"}

    def addtask(self,url='',description=''):
        # 添加任务
        '''
        criticality : 代表业务关键性 10 为一般 30为核心 20是重要
        '''
        data = {"address": url, "description": description, "criticality": "10"}
        try:
            response = requests.post(self.tarurl + "/api/v1/targets", data=json.dumps(data), headers=self.headers, timeout=30,
                                     verify=False)
            result = json.loads(response.content)
            return result['target_id']
        except Exception as e:
            print(str(e))
            return

    def startscan(self,url,description='',profile_id='11111111-1111-1111-1111-111111111111'):
        # 先获取全部的任务.避免重复
        # 添加任务获取target_id
        # 开始扫描
        '''
        11111111-1111-1111-1111-111111111112    High Risk Vulnerabilities
        11111111-1111-1111-1111-111111111115    Weak Passwords
        11111111-1111-1111-1111-111111111117    Crawl Only
        11111111-1111-1111-1111-111111111116    Cross-site Scripting Vulnerabilities
        11111111-1111-1111-1111-111111111113    SQL Injection Vulnerabilities
        11111111-1111-1111-1111-111111111118    quick_profile_2 0   {"wvs": {"profile": "continuous_quick"}}
        11111111-1111-1111-1111-111111111114    quick_profile_1 0   {"wvs": {"profile": "continuous_full"}}
        11111111-1111-1111-1111-111111111111    Full Scan   1   {"wvs": {"profile": "Default"}}
        '''
        targets = self.getscan()
        if url in targets:
            return "repeat"
        else:
            target_id = self.addtask(url,description)
            data = {"target_id": target_id, "profile_id": profile_id,
                    "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
            try:
                response = requests.post(self.tarurl + "/api/v1/scans", data=json.dumps(data), headers=self.headers, timeout=30,
                                         verify=False)
                result = json.loads(response.content)
                print result
                return result['target_id']
            except Exception as e:
                print(str(e))
                return

    def getstatus(self,scan_id):
        # 获取scan_id的扫描大致状况 其中返回的scan_session_id是查看扫描统计信息的重要参数
        try:
            response = requests.get(self.tarurl + "/api/v1/scans/" + str(scan_id), headers=self.headers, timeout=30, verify=False)
            result = json.loads(response.content)
            return result
            # status = result['current_session']['status']
            # 如果是completed 表示结束.可以生成报告
            # if status == "completed":
            #     return self.getreports(scan_id)
            # else:
            #     return result['current_session']['status']
        except Exception as e:
            print(str(e))
            return

    def getScanStatistics(self,scan_id, scan_session_id):
        # 获取扫描的额外其他统计信息
        try:
            response = requests.get(self.tarurl + "/api/v1/scans/" + scan_id + "/results/" + scan_session_id+"/statistics", headers=self.headers,
                                    timeout=30, verify=False)
            results = json.loads(response.content)
            # print results
            print self.tarurl + "/api/v1/scans/" + scan_id + "/results/" + scan_session_id+"/statistics"
            return results
        except Exception as e:
            raise e
            print "GET" + scan_id + "Statistics Failed"

    def getScanDetail(self,scan_id,scan_session_id):
        #获取到某次站点扫描列表
        try:
            response = requests.get(self.tarurl + "/api/v1/scans/" + scan_id + "/results/" + scan_session_id+"/vulnerabilities", headers=self.headers,
                                    timeout=30, verify=False)
            results = json.loads(response.content)
            # print results
            return results
        except Exception as e:
            raise e
            print "GET" + scan_id + "Statistics Failed"

    def delete_scan(self,scan_id):
        # 删除scan_id的扫描
        try:
            response = requests.delete(self.tarurl + "/api/v1/scans/" + str(scan_id), headers=self.headers, timeout=30,
                                       verify=False)
            # 如果是204 表示删除成功
            print self.tarurl + "/api/v1/scans/" + scan_id
            if response.status_code == 204:
                return True
            else:
                return False
        except Exception as e:
            print(str(e))
            return

    def delete_target(self,target_id):
        # 删除target_id的扫描  这个函数有问题
        try:
            response = requests.delete(self.tarurl + "/api/v1/targets/" + str(target_id), headers=self.headers, timeout=30,
                                       verify=False)
            # 如果是204 表示删除成功
            if response.status_code == 204:
                return True
            else:
                return False
        except Exception as e:
            print(str(e))
            return

    def scan_check(self,vuln_id):
        #再次测试某个漏洞
        try:
            response = requests.put(tarurl + "/api/v1/vulnerabilities/1923234603208803719/recheck", headers=headers,
                                    timeout=30,
                                    verify=False)
            # 如果是201 表示添加成功
            print tarurl + "/api/v1/vulnerabilities/" + str(vuln_id) + "/recheck"
            print response.status_code
            if response.status_code == 201:
                print '1111111'
                return True
            else:
                print '222'
                return False
        except Exception as e:
            print '333333333333'
            print(str(e))
            return



    def stop_scan(self,scan_id):
        # 停止scan_id的扫描
        try:
            response = requests.post(self.tarurl + "/api/v1/scans/" + str(scan_id + "/abort"), headers=self.headers, timeout=30,
                                     verify=False)
            # 如果是204 表示停止成功
            if response.status_code == 204:
                return True
            else:
                return False
        except Exception as e:
            print(str(e))
            return

    def scan_status(self):
        # 获取整体的安全状态
        '''
        scans_waiting_count: 等待扫描的数量
        scans_running_count: 正在扫描的数量
        scans_conducted_count: 总扫描数量
        targets_count: 目标总数
        top_vulnerabilities: 漏洞类型排行
        most_vulnerable_targets: 统计了最容易受到攻击的网站

        vuln_count : 整体漏洞数  格式为vuln_count:{med:12,low:123,high:21} 表示所有扫描的站点的总漏洞分贝对应的高中低危漏洞数
        vulnerabilities_open_count: 所有的漏洞数

        '''
        try:
            response = requests.get(self.tarurl + "/api/v1/me/stats", headers=self.headers, timeout=30, verify=False)
            result = json.loads(response.content)
            print result
            return result
        except Exception as e:
            print(str(e))
            return

    def getAllReports(self):
        # 获取所有的报告
        try:
            response = requests.get(self.tarurl + "/api/v1/reports", headers=self.headers, timeout=30, verify=False)
            result = json.loads(response.content)
            return result
        except Exception as e:
            print "Get All Reports Failed!"
            return

    def getreports(self,scan_id):
        # 获取scan_id的HTML扫描报告
        '''
        11111111-1111-1111-1111-111111111111    Developer
        21111111-1111-1111-1111-111111111111    XML
        11111111-1111-1111-1111-111111111119    OWASP Top 10 2013
        11111111-1111-1111-1111-111111111112    Quick
        '''
        data = {"template_id": "11111111-1111-1111-1111-111111111111",
                "source": {"list_type": "scans", "id_list": [scan_id]}}
        try:
            response = requests.post(self.tarurl + "/api/v1/reports", data=json.dumps(data), headers=self.headers, timeout=30,
                                     verify=False)
            result = response.headers
            reporturl =self.tarurl+result['Location']
            response1 = requests.get(reporturl,headers=self.headers,
                                     timeout=30,
                                     verify=False)
            if response1.status_code == 200:
                return True
            else:
                return False
        except Exception as e:
            print(str(e))
            return

    def config(self,url,):
        target_id = self.startscan(url)
        # 获取全部的扫描状态
        data = {
            "excluded_paths": ["manager", "phpmyadmin", "testphp"],
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
            "custom_headers": ["Accept: */*", "Referer:" + url, "Connection: Keep-alive"],
            "custom_cookies": [{"url": url,
                                "cookie": "UM_distinctid=15da1bb9287f05-022f43184eb5d5-30667808-fa000-15da1bb9288ba9; PHPSESSID=dj9vq5fso96hpbgkdd7ok9gc83"}],
            "scan_speed": "moderate",  # sequential/slow/moderate/fast more and more fast
            "technologies": ["PHP"],  # ASP,ASP.NET,PHP,Perl,Java/J2EE,ColdFusion/Jrun,Python,Rails,FrontPage,Node.js
            # 代理
            "proxy": {
                "enabled": False,
                "address": "127.0.0.1",
                "protocol": "http",
                "port": 8080,
                "username": "aaa",
                "password": "bbb"
            },
            # 无验证码登录
            "login": {
                "kind": "automatic",
                "credentials": {
                    "enabled": False,
                    "username": "test",
                    "password": "test"
                }
            },
            # 401认证
            "authentication": {
                "enabled": False,
                "username": "test",
                "password": "test"
            }
        }
        try:
            res = requests.patch(self.tarurl + "/api/v1/targets/" + str(target_id) + "/configuration", data=json.dumps(data),
                                 headers=self.headers, timeout=30 * 4, verify=False)

            data = {"target_id": target_id, "profile_id": "11111111-1111-1111-1111-111111111111",
                    "schedule": {"disable": False, "start_date": None, "time_sensitive": False}}
            try:
                response = requests.post(self.tarurl + "/api/v1/scans", data=json.dumps(data), headers=self.headers, timeout=30,
                                         verify=False)
                result = json.loads(response.content)
                return result['target_id']
            except Exception as e:
                print(str(e))
                return
        except Exception as e:
            raise e

    def getvulnerabilities(self):
        # 获取到所有的漏洞概括
        try:
            response = requests.get(self.tarurl + "/api/v1/vulnerabilities", headers=self.headers, timeout=30, verify=False)
            result = json.loads(response.content)
            print result
            return result
        except Exception as e:
            print(str(e))
            return

    def getscan(self):
        # 获取全部的扫描状态  此函数功能未写全
        targets = []
        try:
            response = requests.get(self.tarurl + "/api/v1/scans", headers=self.headers, timeout=30, verify=False)
            results = json.loads(response.content)
            return results
        except Exception as e:
            raise e

    def getvulnerabilitiesinfo(self,vuln_id):
        # 通过vuln_id获取到具体漏洞详情
        try:
            response = requests.get(self.tarurl + "/api/v1/vulnerabilities/" + vuln_id, headers=self.headers, timeout=30,
                                    verify=False)
            result = json.loads(response.content)
            print self.tarurl + "/api/v1/vulnerabilities/" + vuln_id
            return result
        except Exception as e:
            print(str(e))
            return

    def getvulnerabilitiesinfo1(self, scan_id,scan_session_id,vuln_id):
        # 通过vuln_id获取到具体漏洞详情
        try:
            response = requests.get(self.tarurl + "/api/v1/scans/" + scan_id+'/results/'+scan_session_id+'/vulnerabilities/'+vuln_id, headers=self.headers,
                                    timeout=30,
                                    verify=False)
            result = json.loads(response.content)
            return result
        except Exception as e:
            print(str(e))
            return



    def getScanProfiles(self):
        # 获取到所有扫描策略
        try:
            response = requests.get(self.tarurl + "/api/v1/scanning_profiles", headers=self.headers, timeout=30, verify=False)
            results = json.loads(response.content)
            print results
            return results
        except Exception as e:
            print 'Get ScanProfiles Failed!'

    def getReportTemplates(self):
        # 获取扫描报告模板
        try:
            response = requests.get(self.tarurl + "/api/v1/report_templates", headers=self.headers, timeout=30, verify=False)
            results = json.loads(response.content)
            print results
            return results

        except Exception as e:
            raise e
            print "GET Report template Failed"

    def getTargets(self):
        # 获取到所有的扫描目标
        try:
            response = requests.get(self.tarurl + "/api/v1/targets", headers=self.headers, timeout=30, verify=False)
            results = json.loads(response.content)
            print results
            return results
        except Exception as e:
            print 'Get Targets Failed!'

    def getTargetInformation(self,target_id):
        # 先通过getTargets获取到所有已经扫描的目标站点,再通过target_id获取到扫描站点详情
        # 先获取到已经设置好的target 之后再设置重新修改扫描目标的信息
        try:
            response = requests.get(self.tarurl + "/api/v1/targets/" + target_id, headers=self.headers, timeout=30, verify=False)
            results = json.loads(response.content)
            # print results
            return results

        except Exception as e:
            raise e
            print "GET " + target_id + " Failed!"

    def getTargetConfig(self,target_id):
        # 获取到target_id对应的目标详细配置信息
        try:
            response = requests.get(self.tarurl + "/api/v1/targets/" + target_id + "/configuration", headers=self.headers,
                                    timeout=30, verify=False)
            results = json.loads(response.content)
            print results
            return results
        except Exception as e:
            raise e
            print "GET " + target_id + "configuration Information Failed"

    def setRestartTarget(self,url):
        # 根据之前得到的某个目标的详情,重新获取信息提交,设置再次扫描的目标 复用config()函数 但需要增加变量值
        self.config(self.url)

    def getAllCompletedReport(self):
        # 获取所有已完成扫描的报告
        info = self.getscan()
        for result in info['scans']:
            scan_id = result['scan_id']
            address = result['target']['address']
            status = result['current_session']['status']
            # print 'scan_id: '+scan_id
            # print 'address: '+address
            # print 'status: '+status
            if (status == 'completed'):
                print "address: " + address
                print "report: " + self.getreports(scan_id)

    def getTargetScanID(self,url):
        # 获取到url对应的扫描ID
        info = self.getscan()
        i = 0
        for scan in info['scans']:
            if url == scan['target']['address']:
                scan_id = scan['scan_id']
        return scan_id

    def getTargetStatus(self,url):
        # 获取到url对应的扫描状态   如果扫描完毕直接返回报告,否则,则返回状态信息
        scan_id = self.getTargetScanID(url)
        status = self.getstatus(scan_id)
        if (status == 'failed' and status == 'aborted'):
            return status
        else:
            status = 'completed ' + status
            return status

    if __name__ == '__main__':
        # print getscan()
        # print getTargetStatus("http://oa.fjsmnx.com/")
        # getvulnerabilities()
        # getvulnerabilitiesinfo('1746103617540064477')
        getReportTemplates()
        # getTargetConfig('02f9c8db-598d-441e-a5d0-b9c4af4507fc')
    # print getvulnerabilities()
    # getAllCompletedReport()

    # print getreports('f22d4aa1-e2de-4307-bd9d-ddf3aa531bc1',locals())
    # print config('http://testhtml5.vulnweb.com/')

