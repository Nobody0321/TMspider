#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Created on 2017-11-14 14:34:10
# Project: ThreatMiner

from pyspider.database.mysql.mysqldb import SQL
from fake_useragent import UserAgent
from pyspider.libs.base_handler import *
from pyquery import PyQuery as pq
from lxml import etree

class Handler(BaseHandler):
    crawl_config = {
    }

    @every(minutes= 7*24*60) #一周一次
    def on_start(self):
        ua = UserAgent() # 使用随机的ua
        header = {  
            'user-agent': ua.chrome,
            'cookie': '__cfduid=d0ee9730b3217a46db01739bcc14b5f3e1510043552; PHPSESSID=clejom8trjpt12cnck9afhadi4'
                    }
        self.crawl('https://www.threatminer.org/getReport.php?e=report_list_container&t=0&q=2017',callback=self.index_page, validate_cert=False,headers = header)

    @config(age= 78 * 24 * 60 * 60)#一周一次
    def index_page(self, response):
        ua = UserAgent() # 使用随机的ua
        header = {  
            'referer': 'https://www.threatminer.org',
            'user-agent': ua.chrome,
            'cookie': '__cfduid=d0ee9730b3217a46db01739bcc14b5f3e1510043552; PHPSESSID=clejom8trjpt12cnck9afhadi4'
                    }
        pqObj = pq(response.content)
        #different type of entry Urls should be handled by different methods 
        for each in pqObj('a[href^="domain.php?q="]').items():
            self.crawl('https://www.threatminer.org/'+ each.attr.href, fetch_type='js',callback=self.domain_index_page,headers = header, validate_cert=False)
            
        for each in pqObj('a[href^="host.php?q="]').items():
            self.crawl('https://www.threatminer.org/'+each.attr.href, fetch_type='js',callback=self.host_index_page,headers = header)
            
        for each in pqObj('a[href^="sample.php?q="]').items():
            self.crawl('https://www.threatminer.org/'+each.attr.href, fetch_type='js',callback=self.sample_index_page,headers = header)
            

    def domain_index_page(self, response):
        domain_info =  {
            "name":response.url[41:]
                }
        ua = UserAgent() # 使用随机的ua
        header = {  
            'referer': response.url,
            'user-agent': ua.firefox,
            'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mupql9fn3orau52h2'
                    }
        pqObj = pq(response.content)
        #get uri
        uri_exist= pqObj("div[id = 'uri_container']").text()
        if uri_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=uri_container&q="+domain_info["name"]+"&t=0&rt=3&p=1",callback = self.domain_uri,headers = header, validate_cert=False)
        
        #get pDNS
        pDNS_exist= pqObj("div[id = 'pDNS_container']").text()
        if pDNS_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=pDNS_container&q="+domain_info["name"]+"&t=0&rt=1&p=1",callback = self.domain_pDNS,headers = header, validate_cert=False)
        
        # get sample
        sample_exist = pqObj("div[id = 'related_samples_container']").text()
        if sample_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=related_samples_container&q="+domain_info["name"]+"&t=0&rt=2&p=1",callback = self.domain_sample,headers = header, validate_cert=False)
        
        #get whoisserver
        #get email
            self.crawl("https://www.threatminer.org/getData.php?e=metadata_container&q="+domain_info["name"]+"&t=0&rt=4&p=1",callback = self.domain_info,headers = header, validate_cert=False)     

        #return info


    def host_index_page(self, response):
        host_info =  {
            "name":response.url[39:]
                }
        ua = UserAgent()#使用随机的ua
        header = {  
            'referer': response.url,
            'user-agent': ua.firefox,
            'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mupql9fn3orau52h2'
                    }
        pqObj = pq(response.content)
        #get pDNS
        pDNS_exist = pqObj("div[id = 'pDNS_container']").text()
        if pDNS_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=pDNS_container&q="+host_info["name"]+"&t=1&rt=0&p=1",callback = self.host_pDNS,headers = header, validate_cert=False)
        # get sample
        sample_exist = pqObj("div[id = 'related_samples_container']").text()
        if sample_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=related_samples_container&q="+host_info["name"]+"&t=1&rt=2&p=1",callback = self.host_sample,headers = header, validate_cert=False)
        #get uri
        uri_exist = pqObj("div[id = 'uri_container']").text()
        if uri_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=uri_container&q="+host_info["name"]+"&t=1&rt=3&p=1",callback = self.host_uri,headers = header, validate_cert=False)
    
    #@config(age=10 * 24 * 60 * 60)
    def sample_index_page(self, response):
        sample_info =  {
            "name":response.url[41:]
                }
        ua = UserAgent()#使用随机的ua
        header = {  
            'referer': response.url,
            'user-agent': ua.firefox,
            'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mupql9fn3orau52h2'
                    }
        pqObj = pq(response.content)
        #get filename
        #get filetype
        #get filesize
        #get md5
        self.crawl("https://www.threatminer.org/getData.php?e=metadata_container&q="+sample_info["name"]+"&t=2&rt=5&p=1",callback = self.sample_info,headers = header, validate_cert=False)     
        #get  domain
        domain_exist = pqObj("div[id = 'domains_container']").text()
        if domain_exist !='No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=domains_container&q="+sample_info["name"]+"&t=2&rt=0&p=1",callback = self.sample_domain,headers = header, validate_cert=False)
        # get host
        
        host_exist = pqObj("div[id = 'hosts_container']").text()
        if host_exist != 'No results found.':
            self.crawl("https://www.threatminer.org/getData.php?e=hosts_container&q="+sample_info["name"]+"&t=2&rt=1&p=1",callback = self.sample_host,headers = header, validate_cert=False)

        #return info


    def domain_info(self, response):
        pqObj = pq(response.content)
        newpq = pqObj("td[class=whois_label_column]").items()
        List1 = []
        for each in newpq:
            List1.append(each.next().text())
        return{
            "domain_name":response.url[60:-13],
            'type':'domain',
            'whois_server':List1[1]
                }

    def domain_pDNS(self, response):
        pqObj = pq(response.content)
        List  = set()
        a = pqObj("a[href^='host.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        
        return[{
        "domain_name":response.url[59:-13],
        'type':'domain',
        'pDNS':each
            }for each in List]

    def domain_sample(self, response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='sample.php?q=']").items()
        if a is not None:
            for each in a:    
                List.add(each.text())
        return[{
        "domain_name":response.url[70:-13],
        'type':'domain',
        'related_samples':each
            }for each in List]


    def domain_uri(self,response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='https://www.google.co.uk/search?q=']").items()
        if a is not None:
            for each in a:    
                    List.add(each.text())
        return[{
            "domain_name":response.url[58:-13],
            'type':'domain',
            'uri':each
                }for each in List]

    def host_pDNS(self, response):
        pqObj = pq(response.content)
        List  = set()
        a = pqObj("a[href^='domain.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return[{
            "ip":response.url[59:-13],
            'type':'host',
            'pDNS':each
                }for each in List]

    def host_uri(self,response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='https://www.google.co.uk/search?q=']").items()
        if a is not None:
            for each in a:    
                    List.add(each.text())
        return[{
            "ip":response.url[58:-13],
            'type':'domain',
            'uri':each
                }for each in List]

    def host_sample(self, response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='sample.php?q=']").items()
        if a is not None:
            for each in a:    
                List.add(each.text())
        return[{
            "ip":response.url[70:-13],
            'type':'host',
            'related_samples':each
                }for each in List]
    
    def sample_info(self,response):
        pqObj = pq(response.content)
        keys = pqObj("td[class=whois_label_column]").items()
        values = pqObj("td[class=whois_label_column]").next().items()
        list1 = []
        list2 = []
        for each in keys:
            list1.append(each.text()[:-1])
        for each in values:
            list2.append(each.text())
        nvs = zip(list1,list2)
        nvDict = dict( (name,value) for name,value in nvs)
        result = {
            'filename':nvDict['File name'],
            'filetype':nvDict['File type'],
            'filesize':nvDict['File size'],
            'md5':nvDict['MD5'],
            'analysis_date':nvDict['Analysis date']
        }
        return{    
            "sample_name":response.url[63:-13],
            'type':'sample',
            'filename':result['filename'],
            'filetype':result['filetype'],
            'filesize':result['filesize'],
            'md5':result['md5'],
            'analysis_date':result['analysis_date']
                }

    def sample_domain(self,response):
        pqObj = pq(response.content)
        List  = set()
        a = pqObj("a[href^='domain.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return[{
                "sample_name":response.url[62:-13],
                'type':'sample',
                'domain':each
                    }for each in List]

    def sample_host(self,response):
        pqObj = pq(response.content)
        List  = set()
        a = pqObj("a[href^='host.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return[{
                "sample_name":response.url[60:-13],
                'type':'sample',
                'host':each
                    }for each in List]


    def on_result(self,result):
        if not result:
            return
        sql = SQL()
        type = result.pop('type')
        if type == 'domain':
            sql.insert(tablename='Domains',**result)  
        elif type == 'host':
            sql.insert(tablename='Hosts',**result)  
        elif type == 'sample':
            sql.insert(tablename='Samples',**result)   