from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from  bs4  import BeautifulSoup
from fake_useragent import UserAgent 
import re

def getWhoisserver(bsObj):
        newsoup = bsObj.find_all('td',{'class':"whois_label_column"})
        return newsoup[1].next_sibling.get_text()#rtype : str

def getEmail(bsObj):
    List  = set()
    newsoup = bsObj.find_all('a',href = True)
    if newsoup is not None:
        for each in newsoup: 
            if 'email.php?q=' in each['href']:            
                List.add(each.get_text())
    return  List
    # print(List)       

def getDomainpDNs(bsObj):
    List  = set()
    newsoup = bsObj.find('table',{'class':'table table-bordered table-hover table-striped dataTable no-footer','id':'hosts_table'})
    if newsoup is not None:
        newsoup = newsoup.find_all('td')
        for each in newsoup:
            if each.a is not None:
                if 'host.php?q='  in  each.a['href'] :
                    List.add(each.a.get_text())
    return  List
    # print(List)       

def getSample(bsObj):
    List  = set()
    newsoup = bsObj.find('table',{'class':'table table-bordered table-hover table-striped dataTable no-footer','id':'samples_table'})
    if newsoup is not None:    
        newsoup = newsoup.find_all('td')
        for each in newsoup:
            if each.a is not None:
                if 'sample.php?q='  in  each.a['href'] :
                    List.add(each.a.get_text())
    return  List
    # print(List)       

def getUri(bsObj):
    List  = set()
    newsoup = bsObj.find('table',{'class':'table table-bordered table-hover table-striped dataTable no-footer','id':'uri_table'})
    if newsoup is not None:
        newsoup = newsoup.find_all('td')
        for each in newsoup:
            if each.a is not None:
                if 'https://www.google.co.uk/search?q'  in  each.a['href'] :
                    List.add(each.a.get_text())
    return  List

def getDomainInfo(domainname):
    Dict = {
        'domainname':'',
        'whois_server':'',
        'email':'',
        'pDNS':'',
        'related_sample':'',
        'uri':''
    }
    ua = UserAgent()
    # set phantomJS's agent to Firefox
    dcap = dict(DesiredCapabilities.PHANTOMJS)
    dcap["phantomjs.page.settings.userAgent"] = ua.firefox 
        
    # system path you need to config by yourself
    phantomjsPath = "/usr/lib/phantomjs/phantomjs"
    driver = webdriver.PhantomJS(executable_path=phantomjsPath, desired_capabilities=dcap)

    url = "https://www.threatminer.org/domain.php?q="+ domainname
    driver.get(url)
    soup = BeautifulSoup(driver.page_source,'lxml')

    Dict['domainname'] = domainname
    Dict['whois_server'] = getWhoisserver(soup)
    Dict['email'] = getEmail(soup)
    Dict['pDNS'] = getDomainpDNs(soup)
    Dict['related_sample'] = getSample(soup)
    Dict['uri'] = getUri(soup)

    driver.quit()
    return Dict
    
