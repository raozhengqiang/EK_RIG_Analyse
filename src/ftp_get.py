from ftplib import FTP
import os,sys
import datetime
import ConfigParser
class CaseGenerater(object):
    def __init__(self):
        pass
        
    def get_wrs_data(self,data_str,parent_dir):
        ftp = FTP()
        ftp.connect('10.5.36.63')
        ftp.login('ftpuser','gxfc,hbnl!!!')
        print ftp.getwelcome()
        cf = ConfigParser.ConfigParser()
        os.chdir(parent_dir)
        parent_dir=os.getcwd()
        print parent_dir
        cf_file=os.path.join(parent_dir,'conf_yar','type.conf')

        
        cf.read(cf_file)
        ftp_path=cf.get("ftp","ftp_path")
        
        ftp.cwd(ftp_path)
        ftp.retrlines("List")
        bufsize = 1024
        filename='wrs_' + data_str + '_extract.txt'
        #filename1 ='/opt/exploitkit_automation/'+'wrs_' + data_str + '_extract.txt'
        filename1=os.path.join(parent_dir,'crawl_file',filename)
        ftp.retrbinary('RETR %s'%filename,open(filename1,'wb').write)
        ftp.quit
        print "get {}!".format(filename)
        return filename

    def generate_url_to_crawl(self, src_file):
        referer_url_set = set()
        parent_dir, file_name_suffix = os.path.split(src_file)
        #parent_dir="/opt/exploitkit_automation/"
        parent_dir=os.getcwd()

        
        file_name, suffix = os.path.splitext(file_name_suffix)
        print file_name, suffix
        dst_file = os.path.join(parent_dir,'crawl_file',file_name+'_crawl'+suffix)
        src_file=os.path.join(parent_dir,'crawl_file',src_file)
        
        fh = open(dst_file, 'w+')
        file_open = open(src_file,'r')
        num_count = 0
        write_count = 0
        
        for line_str in file_open.readlines():
            num_count += 1
            line_list = line_str.strip().split('\t')
            if num_count == 1:
                try:
                    referer_url_index = line_list.index("Referer URL")
                    country_index = line_list.index("Client Country")
                    ek_name_index = line_list.index("EK Name")
                    campaign_name_index = line_list.index("Campaign Name")
                    url_index = line_list.index("Full URL")
                except:
                    print "no index"
                    return
            else:
                referer_url = line_list[referer_url_index]
                ek_name = line_list[ek_name_index]
                
                if referer_url in referer_url_set or 'RIG' not in ek_name:
                    continue
                else:
                    referer_url_set.add(referer_url)
                
                if len(referer_url) != 0 and referer_url is not '-':
                    write_count += 1
                    
                    write_line = "%s\t%s\t%s\t%s\t%s\n"%(referer_url, ek_name, line_list[campaign_name_index], line_list[country_index], line_list[url_index])
                    fh.writelines(write_line)
                    if write_count == 10:
                        break
        fh.close()
    
    def generate_wrs_case(self, date_str,parent_dir):
        wrs_file = self.get_wrs_data(date_str,parent_dir)
        self.generate_url_to_crawl(wrs_file)
def getYesterday(): 
    today=datetime.date.today() 
    oneday=datetime.timedelta(days=1) 
    yesterday=today-oneday  
    return yesterday.strftime("%Y%m%d")

def main(date_str,parent_dir):
    case_generater = CaseGenerater()
    case_generater.generate_wrs_case(date_str,parent_dir)
    


def print_help():
    print "python ftp_get.py date parent_dir"

if __name__ == "__main__":
    if sys.argv[1] != 'latest':
        date_str = sys.argv[1]
    else:
        date_str = getYesterday()
	print date_str
    #if len(sys.argv)!=2:
        #print_help()
    parent_dir=sys.argv[2]
   
    main(date_str,parent_dir)

