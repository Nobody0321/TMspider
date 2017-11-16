from bs4 import BeautifulSoup
import random
import time
from fake_useragent import UserAgent

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.proxy import Proxy
from selenium.webdriver.common.proxy import ProxyType

from HostInfoSpider import *
from DomainInfoSpider import *
from SampleInfoSpider import *
from EmailInfoSpider import *

import json

wait = 20
ua = UserAgent()
def getProxy():
    file =  open("freeProxy.txt",'r')
    List = file.read().split("\n")
    for each in List:
        if  ':' not in each:
            List.remove(each)
    return List

proxies = getProxy()
#为了反爬，使用代理、伪装UA、设置较大的爬取间隔

# set phantomJS's agent to Firefox or whatever
dcap = dict(DesiredCapabilities.PHANTOMJS)
dcap["phantomjs.page.settings.userAgent"] = ua.firefox 
    
# system path you need to config by yourself, in ubuntu Linux, it should be "/usr/lib/phantomjs/phantomjs"
phantomjsPath = "/usr/lib/phantomjs/phantomjs"
driver = webdriver.PhantomJS(executable_path=phantomjsPath, desired_capabilities=dcap)

def getReportPagesoup():#get all report urls to crawl
    UrlList = []
    baseUrl = "https://www.threatminer.org/getReport.php?e=report_list_container&t=0&q="
    Years = [ "2017"]
    #considering the timeliness, we only crawl reports expressed in recent years 
    for year in Years:
        Url = baseUrl + year
        driver.get(Url)
        # print(driver.page_source)
        soup = BeautifulSoup(driver.page_source,'lxml')
    return soup

def getDomains(soup):
    DomainNames = [] 
    List = soup.findAll("a",href=True)
    for each in List:
        if 'domain.php?q=' in each['href']:
            each = each.get_text()
            if each is not '':
                DomainNames.append(each)
    return  DomainNames

def getHosts(soup):
    HostNames = [] 
    List = soup.findAll("a",href=True)
    for each in List:
        if 'host.php?q=' in each['href']:
            each = each.get_text()
            if each is not '':
                HostNames.append(each)
    return  HostNames

def getSamples(soup):
    SampleNames = [] 
    List = soup.findAll("a",href=True)
    for each in List:
        if 'sample.php?q=' in each['href']:
            each = each.get_text()
            if each is not '':
                SampleNames.append(each)
    return  SampleNames

def getEmails(soup):
    EmailNames = [] 
    List = soup.findAll("a",href=True)
    for each in List:
        if 'email.php?q=' in each['href']:
            each = each.get_text()
            if each is not '':
                EmailNames.append(each)
    return  EmailNames

def ReadFile(filename):
    file = open('Files/'+filename,'r')
    List = file.read().split('\n')
    file.close()
    return List

def WriteFile(filename,List):
    file = open('Files/'+filename,'a')
    for each in List:
        file.write(each+ '\n')
    file.close() 

def NameSpider():
    # on each report site, we'll get all those domain,hosts,smaple,email names/urls for furthur crawling
    ReportUrlList = getReportUrl()
    namefile = open('Files/ReportUrl.txt','w')
    for reportUrl in ReportUrlList:
        driver.get(reportUrl)
        soup = BeautifulSoup(driver.page_source,'lxml')
        Domainnames = getDomains(soup)
        Hostnames = getHosts(soup)
        Samplenames = getSamples(soup)
        Emailnames = getEmails(soup)
        print(reportUrl)
        namefile.write(reportUrl)
        WriteFile('DomainNames.txt',Domainnames)
        print('1')
        WriteFile('HostNames.txt',Hostnames)
        print('2')
        WriteFile('SampleNames.txt',Samplenames)
        print('3')
        WriteFile('EmailNames.txt',Emailnames)
        print('4')
        time.sleep(wait)
    namefile.close()

def InfoSpider():
    Domainnames = ReadFile('DomainNames.txt')
    file = open('File/DomainInfo.json', 'a')
    for each in  Domainnames:
        if each  != '':
            dic = getDomainInfo(each)
            jsObj = json.dumps(dic)
            file.write(jsObj)
            print("Domain info: \n" + each)
    file.close()

    Hostnames = ReadFile('HostNames.txt')
    file = open('File/HostInfo.json', 'a')
    for each in  Hostnames:
        if each  != '':
            dic = getHostInfo(each)
            jsObj = json.dumps(dic)
            file.write(jsObj)
            print("Host info: \n" + each)
    file.close()

    Samplenames = ReadFile('SampleNames.txt')
    file = open('File/SampleInfo.json', 'a')
    for each in  Hostnames:
        if each  != '':
            dic = getSampleInfo(each)
            jsObj = json.dumps(dic)
            file.write(jsObj)
            print("Sample info: \n" + each)
    file.close()

    Emailnames = ReadFile('EmailNames.txt')
    file = open('File/EmailInfo.json', 'a')
    for each in  Hostnames:
        if each  != '':
            dic = getEmailInfo(each)
            jsObj = json.dumps(dic)
            file.write(jsObj)
            print("Email info: \n" + each)
    file.close()

if __name__ == '__main__':
    NameSpider()
    InfoSpider()