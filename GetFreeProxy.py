# -*- coding: utf-8 -*-
# !/usr/bin/env python

import re
import requests
from lxml import etree
import random
import time
from requests import packages
import urllib3


# for debug to disable insecureWarning
requests.packages.urllib3.disable_warnings()


class WebRequest(object):
    def __init__(self, *args, **kwargs):
        pass

    @property
    def user_agent(self):
  
        ua_list = [
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
            'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
            'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
            'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0'
        ]
        return random.choice(ua_list)

    @property
    def header(self):
        """
        basic header
        :return:
        """
        return {'User-Agent': self.user_agent,
                'Accept': '*/*',
                'Connection': 'keep-alive',
                'Accept-Language': 'zh-CN,zh;q=0.8'}

    def get(self, url, header=None, retry_time=5, timeout=30,
            retry_flag=list(), retry_interval=5, *args, **kwargs):
        """
        get method
        :param url: target url
        :param header: headers
        :param retry_time: retry time when network error
        :param timeout: network timeout
        :param retry_flag: if retry_flag in content. do retry
        :param retry_interval: retry interval(second)
        :param args:
        :param kwargs:
        :return:
        """
        headers = self.header
        if header and isinstance(header, dict):
            headers.update(header)
        while True:
            try:
                html = requests.get(url, headers=headers, timeout=timeout)
                # if filter(lambda key: key in html.content, retry_flag):
                # ԭfilter���ִ��if�ж����������ΪTrue�����python3��python2������
                # python3��filter����filter���󣬼�ʹΪ�գ�if���ж�ΪTrue
                # python2��filter����list����Ϊ�գ�if�ж�ΪFalse
                for f in retry_flag:
                    if f in html.content:
                        raise Exception
                return html
            except Exception as e:
                print(e)
                retry_time -= 1
                if retry_time <= 0:
                    return
                time.sleep(retry_interval)


def getHtmlTree(url):
        """
        ��ȡhtml��
        :param url:
        :param kwargs:
        :return:
        """
        header = {'Connection': 'keep-alive',
                  'Cache-Control': 'max-age=0',
                  'Upgrade-Insecure-Requests': '1',
                  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko)',
                  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                  'Accept-Encoding': 'gzip, deflate, sdch',
                  'Accept-Language': 'zh-CN,zh;q=0.8'
                  }
        # TODO ȡ����������ô������������
        wr = WebRequest()
        html = wr.get(url=url, header=header).content
        return etree.HTML(html)


def freeProxyFirst(page=10):
        """
        ץȡ���Ǵ��� http://www.data5u.com/
        :param page: ҳ��
        :return:
        """
        url_list = ['http://www.data5u.com/',
                    'http://www.data5u.com/free/',
                    'http://www.data5u.com/free/gngn/index.shtml',
                    'http://www.data5u.com/free/gnpt/index.shtml']
        for url in url_list:
            html_tree = getHtmlTree(url)
            ul_list = html_tree.xpath('//ul[@class="l2"]')
            for ul in ul_list:
                yield ':'.join(ul.xpath('.//li/text()')[0:2])


def freeProxySecond(proxy_number=100):
        """
        ץȡ����66 http://www.66ip.cn/
        :param proxy_number: ��������
        :return:
        """
        url = "http://www.66ip.cn/mo.php?sxb=&tqsl={}&port=&export=&ktip=&sxa=&submit=%CC%E1++%C8%A1&textarea=".format(
            proxy_number)
        request = WebRequest()
        # html = request.get(url).content
        # contentΪδ���룬textΪ�������ַ���
        html = request.get(url).text
        for proxy in re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}', html):
            yield proxy


def freeProxyThird(days=1):
        """
        ץȡip181 http://www.ip181.com/
        :param days:
        :return:
        """
        url = 'http://www.ip181.com/'
        html_tree = getHtmlTree(url)
        tr_list = html_tree.xpath('//tr')[1:]
        for tr in tr_list:
            yield ':'.join(tr.xpath('./td/text()')[0:2])


def freeProxyFourth():
        """
        ץȡ���̴��� http://api.xicidaili.com/free2016.txt
        :return:
        """
        url_list = ['http://www.xicidaili.com/nn',  # ����
                    'http://www.xicidaili.com/nt',  # ͸��
                    ]
        for each_url in url_list:
            tree = getHtmlTree(each_url)
            proxy_list = tree.xpath('.//table[@id="ip_list"]//tr')
            for proxy in proxy_list:
                yield ':'.join(proxy.xpath('./td/text()')[0:2])


def freeProxyFifth():
        """
        ץȡguobanjia http://www.goubanjia.com/free/gngn/index.shtml
        :return:
        """
        url = "http://www.goubanjia.com/free/gngn/index{page}.shtml"
        for page in range(1, 10):
            page_url = url.format(page=page)
            tree = getHtmlTree(page_url)
            proxy_list = tree.xpath('//td[@class="ip"]')
            # ����վ�����ص����ָ��ţ���ץȡ����������ֻ�.����
            # ��Ҫ���˵�<p style="display:none;">������
            xpath_str = """.//*[not(contains(@style, 'display: none'))
                                and not(contains(@style, 'display:none'))
                                and not(contains(@class, 'port'))
                                ]/text()
                        """
            for each_proxy in proxy_list:
                # :���ŷ���td�£���������div span p�У��ȷָ��ҳ�ip������port
                ip_addr = ''.join(each_proxy.xpath(xpath_str))
                port = each_proxy.xpath(".//span[contains(@class, 'port')]/text()")[0]
                yield '{}:{}'.format(ip_addr, port)

def GetFreeProxy():
    freeProxyFirst1 = open("freeProxy.txt", "w", encoding='utf-8')
    for e in freeProxyFirst():
        freeProxyFirst1.write(e + '\n')
        print(e)

    freeProxySecond2 = open("freeProxy.txt", "a", encoding='utf-8')
    for e in freeProxySecond():
        print(e)
        freeProxySecond2.write(e + '\n')

    freeProxyThird3 = open("freeProxy.txt", "a", encoding='utf-8')
    for e in freeProxyThird():
        freeProxyThird3.write(e + '\n')
        print(e)

    freeProxyFourth4 = open("freeProxy.txt", "a", encoding='utf-8')
    for e in freeProxyFourth():
        freeProxyFourth4.write(e + '\n')
        print(e)

    freeProxyFifth5 = open("freeProxy.txt", "a", encoding='utf-8')
    for e in freeProxyFifth():
        freeProxyFifth5.write(e + '\n')
        print(e)


if __name__ == '__main__':
    GetFreeProxy()
