#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Created on 2017-11-14 14:34:10
# Project: ThreatMiner

from fake_useragent import UserAgent
from pyspider.libs.base_handler import *
from pyquery import PyQuery as pq
from lxml import etree

class Handler(BaseHandler):
    crawl_config = {
        
    }

    @every(minutes= 60) #一小时一次
    def on_start(self):
        ua = UserAgent()#使用随机的ua
        header = {  
    'user-agent': ua.chrome,
    'cookie': '__cfduid=d0ee9730b3217a46db01739bcc14b5f3e1510043552; PHPSESSID=clejom8trjpt12cnck9afhadi4'
                    }
        self.crawl('https://www.threatminer.org/getReport.php?e=report_list_container&t=0&q=2017',callback=self.index_page, validate_cert=False,headers = header)

    #@config(age= 24 * 60 * 60)#一天一次
    def index_page(self, response):
        ua = UserAgent()#使用随机的ua
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
        info =  {
            "name":response.url[41:],
            "type":response.url[28:34]
                }
        ua = UserAgent()#使用随机的ua
        header = {  
    'referer': response.url,
    'user-agent': ua.firefox,
    'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mupql9fn3orau52h2'
                    }
        #get uri
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=uri_container&q="+info["name"]+"&t=0&rt=3&p=1",callback = self.domain_uri,headers = header, validate_cert=False)
        except Exception:
            pass
        #get pDNS
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=pDNS_container&q="+info["name"]+"&t=0&rt=1&p=1",callback = self.domain_pDNS,headers = header, validate_cert=False)
        except Exception:
            pass
        # get sample
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=related_samples_container&q="+info["name"]+"&t=0&rt=2&p=1",callback = self.domain_sample,headers = header, validate_cert=False)
        except Exception:
            pass
        #get whoisserver
        #get email
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=metadata_container&q="+info["name"]+"&t=0&rt=4&p=1",callback = self.domain_info,headers = header, validate_cert=False)     
        except Exception:
            pass


        #return info


    def host_index_page(self, response):
        info =  {
            "name":response.url[40:],
            "type":response.url[28:32]
                }
        ua = UserAgent()#使用随机的ua
        header = {  
    'referer': response.url,
    'user-agent': ua.firefox,
    'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mupql9fn3orau52h2'
                    }
        #get pDNS
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=pDNS_container&q="+info["name"]+"&t=1&rt=0&p=1",callback = self.host_pDNS,headers = header, validate_cert=False)
        except Exception:
            pass
        # get sample
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=related_samples_container&q="+info["name"]+"&t=1&rt=2&p=1",callback = self.host_sample,headers = header, validate_cert=False)
        except Exception:
            pass
        
        #return info
    
    @config(age=10 * 24 * 60 * 60)
    def sample_index_page(self, response):
        info =  {
            "name":response.url[41:],
            "type":response.url[28:34]
                }
        ua = UserAgent()#使用随机的ua
        header = {  
    'referer': response.url,
    'user-agent': ua.firefox,
    'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mupql9fn3orau52h2'
                    }
        #get filename
        #get filetype
        #get filesize
        #get md5
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=metadata_container&q="+info["name"]+"&t=2&rt=5&p=1",callback = self.sample_info,headers = header, validate_cert=False)     
        except Exception:
            pass
        #get  domain
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=domains_container&q="+info["name"]+"&t=2&rt=0&p=1",callback = self.sample_domain,headers = header, validate_cert=False)
        except Exception:
            pass
        # get host
        try:
            self.crawl("https://www.threatminer.org/getData.php?e=related_sample_container&q="+info["name"]+"&t=2&rt=1&p=1",callback = self.sample_host,headers = header, validate_cert=False)
        except Exception:
            pass

        #return info


    def domain_info(self, response):
        pqObj = pq(response.content)
        newpq = pqObj("td[class=whois_label_column]").items()
        List1 = []
        for each in newpq:
            List1.append(each.next().text())
        return{
            'domainname':List1[0],
            'whois server':List1[1]
                }

    def domain_pDNS(self, response):
        pqObj = pq(response.content)
        List  = set()
        a = pqObj("a[href^='host.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return{
            'domain pDNS':List
                }

    def domain_sample(self, response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='sample.php?q=']").items()
        if a is not None:
            for each in a:    
                List.add(each.text())
        return{
            'domain samples':List
                }

    def domain_uri(self,response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='https://www.google.co.uk/search?q=']").items()
        if a is not None:
            for each in a:    
                    List.add(each.text())
        return{
            'domain uri':List
                }


    def host_pDNS(self, response):
        pqObj = pq(response.content)
        List  = set()
        a = pqObj("a[href^='domain.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return{
            'host pDNS':List
                }


    def host_sample(self, response):
        pqObj = pq(response.content)
        List = set()
        a = pqObj("a[href^='sample.php?q=']").items()
        if a is not None:
            for each in a:    
                List.add(each.text())
        return{
            'host samples':List
                }
    
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
            'filenmame':nvDict['File name'],
            'filetype':nvDict['File type'],
            'filesize':nvDict['File size'],
            'md5':nvDict['MD5']
        }
        return{
            'sample info':result
                }

    def sample_domain(self,response):
        List  = set()
        a = pqObj("a[href^='domain.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return{
            'sample domain':List
                }

    def sample_host(self,response):
        List  = set()
        a = pqObj("a[href^='host.php?q=']").items()
        if a is not None:
            for each in a:               
                List.add(each.text())
        return{
            'sample host':List
                }
