from pyquery import PyQuery as pq
from lxml import etree
from bs4 import BeautifulSoup
import  re

file = open('/media/chen/0869079108690791/实验室/工作/diy/DomainNames.txt')
List = file.readlines()
a = 1
# for each in List:
url = 'https://www.threatminer.org/getData.php?e=related_sample_container&q=ea5b3320c5bbe2331fa3c0bd0adb3ec91f0aed97709e1b869b79f6a604ba002f&t=2&rt=1&p=1'
try: 
    pqObj = pq(url)
    print('ok')
except Exception:
    pass
print('123')