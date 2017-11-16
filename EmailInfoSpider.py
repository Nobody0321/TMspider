from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from  bs4  import BeautifulSoup
from fake_useragent import UserAgent 
import re
   
def getDomain(bsObj):
    List  = set()
    newsoup = bsObj.find_all('a',href = True)
    if newsoup is not None:
        for each in newsoup:
            if 'domain.php?q=' in each['href']:
                List.add(each.get_text())
    return  List  

def getEmailInfo(EmailAddress):
    Dict = {
        'emailaddress':'',
        'domain':''
        }
    ua = UserAgent()
    # set phantomJS's agent to Firefox
    dcap = dict(DesiredCapabilities.PHANTOMJS)
    dcap["phantomjs.page.settings.userAgent"] = ua.firefox 
        
    # system path you need to config by yourself
    phantomjsPath = "/usr/lib/phantomjs/phantomjs"
    driver = webdriver.PhantomJS(executable_path=phantomjsPath, desired_capabilities=dcap)

    url = "https://www.threatminer.org/email.php?q="+ samplename
    driver.get(url)
    soup = BeautifulSoup(driver.page_source,'lxml')

    Dict['emailaddress'] = EmailAddress
    Dict['domain'] = getDomain (soup)

    driver.quit()
    return Dict
    
