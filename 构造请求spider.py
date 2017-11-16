#由于selenium爬取网站需要翻页，我们决定构造ajax请求，爬取threatMiner
from fake_useragent import UserAgent

ua = UserAgent()

mainheader = {  
    'referer': 'https://www.threatminer.org/',
    'user-agent': ua.chrome,
    'cookie': '__cfduid=d2d01e0d2940fe70f3713db86739539811508833807; PHPSESSID=6konc53n5mubsl9fn3orau52h2'
}

#在每个报告页面，请求的每一条domain\host\email\relate_sample的URL
#对该页面进行处理可以获得
def RequestEntryUrl(ReportUrl, entrytype):  
        if entrytype == 'domain':
            addUrl = "getReport.php?e=domains_container&q="+ReportUrl[40:-7] +"&t=3&rt=0&p=undefined"
        elif entrytype =='host':
            addUrl = "getReport.php?e=hosts_container&q=" + ReportUrl[40:-7] + "&t=3&rt=1&p=undefined"
        elif entrytype =='email':
            addUrl = "getReport.php?e=emails_container&q=" + ReportUrl[40:-7] + "&t=3&rt=2&p=undefined"
        elif entrytype == 'relatedsample':
            addUrl = "getReport.php?e=related_samples_container&q=" + ReportUrl[40:-7]+ "&t=3&rt=3&p=undefined"
        #后期应该在此处添加异常处理，防止输入的entrytype不合法
        
        return addUrl

#访问上面这个函数生成的url要用到的header，是查看每个报告中所有条目的header
def RequestEntryHeader(ReportName, header): 
    header['referer'] = header['referer'] + "report.php?q=" + ReportName
    return header
    
def RequestEntryInfoUrl(entryname,infoname):
    if infoname == "whois":
        addUrl = "getData.php?e=whois_container&q=" + entryname + "&t=0&rt=4&p=1"
    elif infoname == "url":
        addUrl = "getData.php?e=uri_container&q=" + entryname + "&t=0&rt=3&p=1"
    elif infoname == "pdns":
        addUrl = "getData.php?e=pDNS_container&q=" + entryname + "&t=0&rt=1&p=1"
    elif infoname == "pDNS":
        addUrl = "getData.php?e=pDNS_container&q=" + entryname + "&t=0&rt=1&p=1"
    elif infoname == "related_samples":
        addUrl = "getData.php?e=related_samples_container&q=" + entryname + "&t=0&rt=2&p=1"
    return "https://www.threatminer.org/" + addUrl
    
    
#访问各个条目(类型：domain, host, email,realated_sample)详情页面的header，访问上面函数生成的url要用到
def RequestEntryInfoHeader(entrytype, entryname, header):
    header['referer'] = header['referer'] + entrytype +'.php?q='+ entryname
    return header