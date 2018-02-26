import urllib2
import time, datetime
import os,sys
import re
import csv
import hashlib
import paramiko
from parse_wrs import WRSParser

class UrlManager(object):
    def __init__(self):
        self.new_urls = set()
        self.old_urls = set()

    def add_new_url(self,url):
        if url is None:
            return
        if url not in self.new_urls and url not in self.old_urls:
            self.new_urls.add(url)

    def add_new_urls(self,urls):
        if urls is None or len(urls)==0:
            return
        for url in urls:
            self.add_new_url(url)

    def has_new_url(self):
        return len(self.new_urls)!=0

    def get_new_url(self):
        new_url =  self.new_urls.pop()
        self.old_urls.add(new_url)
        return new_url

class HtmlDownloader(object):
    def download(self,url):
        if url is None:
            return None
        request = urllib2.Request(url)
        response = urllib2.urlopen(request)
        if response.getcode() != 200:
            return  None
        return response.read(),response.info().headers

class SpiderMain(object):
    def __init__(self):
        self.urls = UrlManager()
        self.downloader = HtmlDownloader()
        self.soup = None
        self.html_cont = None
        self.html_header = None

    def craw(self):
        try:
            new_url = self.urls.get_new_url()
            self.html_cont, self.html_header = self.downloader.download(new_url)
        except:
            print 'craw failed'
        return self.html_cont, self.html_header
    
    def craw_url(self, full_url, file_path):
        self.urls.add_new_url(full_url)
        while self.urls.has_new_url():
            content, header = self.craw()
            if content is None:
                break
            try:
                spider_file = open(file_path, "w")
                spider_file.write(content)
                spider_file.close()
            except:
                print "crawl %s failed!" %full_url
             

def getYesterday(): 
    today=datetime.date.today() 
    oneday=datetime.timedelta(days=1) 
    yesterday=today-oneday  
    return yesterday.strftime("%Y%m%d")
             
def sftp_upload(file_name):
    t = paramiko.Transport(sock=("nj-vl.trendmicro.com.cn", 3389))
    t.connect(username="ftpuser", password="gxfc,hbnl!!!")
    sftp = paramiko.SFTPClient.from_transport(t)
    remote_path = "/ftp/sa/chaoying/sample_sourcing/"
    local_path = "./"
    remote_file = remote_path + file_name
    local_file = local_path + file_name
    sftp.put(local_file, remote_file)
    print "upload successfully!"
    t.close()

def main():
    wrs_root_url = "http://ekportal.wrs.trendmicro.com/url_analyze/api/db/wrs/obj/get/url/date%20"
    if sys.argv[1] != 'latest':
        date_str = sys.argv[1]
    else:
        date_str = getYesterday()
        
    wrs_full_url = wrs_root_url + date_str + '/'
    print "start craw {}".format(wrs_full_url)

    crawl_file_path = "C:\Users\zhengqiang_rao\Desktop\cuckoo\wrs_{}.txt".format(date_str)
    obj_spider = SpiderMain()
    obj_spider.craw_url(wrs_full_url, crawl_file_path)
    file_parser = WRSParser(crawl_file_path)
    parse_result_file_path = file_parser.start_extract()
    print parse_result_file_path
    parent_dir, parse_result_file_path = os.path.split(parse_result_file_path)
    print parse_result_file_path
    
    if len(sys.argv) == 3 and sys.argv[2] == 'upload':
        try:
            sftp_upload(parse_result_file_path)
        except:
            print "upload via sftp failed!"
        
def print_help():
    print """
python spider_wrs_by_date.py date(yymmdd)|latest [upload]

    """

if __name__=="__main__":
    if len(sys.argv) == 1:
        print_help()
    else:
        main()




