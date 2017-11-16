from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from  bs4  import BeautifulSoup
from fake_useragent import UserAgent 
import re  

def getpDNS(bsObj):
    List  = set()
    newsoup = bsObj.find('table',{'class':'table table-bordered table-hover table-striped dataTable no-footer','id':'domains_table'})
    if newsoup is not None:
        newsoup = newsoup.find_all('td')
        for each in newsoup:
            if each.a is not None:
                if 'domain.php?q='  in  each.a['href'] :
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
                if 'https://www.google.co.uk/search?q='  in  each.a['href'] :
                    List.add(each.a.get_text())
    return  List

def getHostInfo(hostname):
    Dict = {
        'ip':'',
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

    url = "https://www.threatminer.org/host.php?q="+ hostname
    driver.get(url)
    soup = BeautifulSoup(driver.page_source,'lxml')

    Dict['ip'] = hostname
    Dict['pDNS'] = getpDNS(soup)
    Dict['related_sample'] = getSample(soup)
    Dict['uri'] = getUri(soup)

    driver.quit()
    return Dict
    
