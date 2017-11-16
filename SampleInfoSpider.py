from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from  bs4  import BeautifulSoup
from fake_useragent import UserAgent 
import re
   
def getFilename(bsObj):
    newsoup = bsObj.find_all('td',{'class':"whois_label_column"})
    return newsoup[0].next_sibling.get_text()#rtype : str

def getFiletype(bsObj):        
    newsoup = bsObj.find_all('td',{'class':"whois_label_column"})
    return newsoup[1].next_sibling.get_text()#rtype : str

def getFilesize(bsObj):
    newsoup = bsObj.find_all('td',{'class':"whois_label_column"})
    return newsoup[2].next_sibling.get_text()#rtype : str

      
def getMD5(bsObj):#待完成
    newsoup = bsObj.find_all('td',{'class':"whois_label_column"})
    return newsoup[4].next_sibling.get_text()#rtype : str

def getDomain(bsObj):
    List  = set()
    newsoup = bsObj.find_all('a',href = True)
    if newsoup is not None:
        for each in newsoup:
            if 'domain.php?q=' in each['href']:
                List.add(each.get_text())
    return  List  

def getHost(bsObj):
    List  = set()
    newsoup = bsObj.find_all('a',href = True)
    if newsoup is not None:
        for each in newsoup:
            if 'host.php?q=' in each['href'] :
                List.add(each.get_text())
    return  List

def getSampleInfo(samplename):
    Dict = {
        'sample_name':'',
        'filename':'',
        'filetype':'',
        'filesize':'',
        'md5':'',
        'domain':'',
        'host':''
    }
    ua = UserAgent()
    # set phantomJS's agent to Firefox
    dcap = dict(DesiredCapabilities.PHANTOMJS)
    dcap["phantomjs.page.settings.userAgent"] = ua.firefox 
        
    # system path you need to config by yourself
    phantomjsPath = "/usr/lib/phantomjs/phantomjs"
    driver = webdriver.PhantomJS(executable_path=phantomjsPath, desired_capabilities=dcap)

    url = "https://www.threatminer.org/sample.php?q="+ samplename
    driver.get(url)
    soup = BeautifulSoup(driver.page_source,'lxml')

    Dict['sample_name'] = samplename
    Dict['filename'] = getFilename(soup)
    Dict['filetype'] = getFiletype (soup)
    Dict['filesize'] = getFilesize(soup)
    Dict['md5'] = getMD5(soup)
    Dict['domain'] = getDomain(soup)
    Dict['host'] = getHost(soup)

    driver.quit()
    return Dict
    
