import sys
import ConfigParser
sys.path.append("/opt/exploitkit_automation/util/")
import json
import os
import re
import shutil
import time
import hashlib
import pexpect
from multiprocessing import Process,Queue
import subprocess
#from generate_result import *
import datetime
from cuckoo.misc import set_cwd
from operate_mysql import operate_database

from cuckoo.core.database import Database
from state_analyse import state_analyse
import time

class StartCuckoo:
    def __init__(self):
        #self.tmp_file = '/opt/exploitkit_automation/tmp.txt'
        """
        self.result_root_path = self.config_["result_root_path"]
        self.vpn_path = self.config_["vpn_path"]
        """
        self.result_root_path = "."
        
        
        self.vpn_path = "/home/chaoying/vpn/"
        self.vpn_cmd = []
        #self.analyse_root_path = r'/opt/cuckoo/storage/analyses'
        #if not os.path.exists(self.analyse_root_path):
            #print "check cuckoo path!"
        self.username = 'ob4sxwjjdlmt31yfmx4clih1'
        self.password = 'alma6x6bv41xcvubh1hoti52'
        self.vpn_log_path = None
        self.result_file_path = "result_file_{}.txt".format(time.strftime('%Y%m%d%H%M%S', time.localtime()))
        self.choosed_vpn_path = None

    def config_vpn(self,country_name):
        self.vpn_cmd = []
        for vpn_name in os.listdir(self.vpn_path):
            if country_name in vpn_name:
                cmd_tmp = 'openvpn --config {}{}'.format(self.vpn_path,vpn_name)
                self.vpn_cmd.append(cmd_tmp)

    def use_vpn(self,choosed_url):
        #in father process ,start vpn
        #in child process,start cuckoo and colse vpn
        if len(self.vpn_cmd) == 0:
            print "no this country!"
            return
        for choosed_vpn in self.vpn_cmd:
            print "start exeuce {}".format(choosed_vpn)
            child = pexpect.spawn(choosed_vpn)
            file_name = "{}_{}.log".format(choosed_vpn.split('/')[-1],time.strftime('%Y%m%d%H%M%S', time.localtime()))
            log_file = self.vpn_log_path + file_name
            fout = file(log_file,'w')
            child.logfile = fout
            child.expect("Enter Auth Username:")
            child.sendline(self.username)
            child.expect("Enter Auth Password:")
            child.sendline(self.password)
            i = -1
            try:
              	i = child.expect("Initialization Sequence Completed",timeout=500)
            except:
                print("config vpn failed!")
            print i
            if i == 0:
                print "open vpn!"
                self.choosed_vpn_path = None
                self.choosed_vpn_path = choosed_vpn.split('/')[-1]
                self.start_cuckoo(choosed_url)
                time.sleep(5)
            child.sendcontrol('c')
            child.interact()
            if i == 0:
                break
    '''
    def start_cuckoo1(self,url):
        cmd = 'cuckoo submit --url {}>{}'.format(url.split()[0], self.tmp_file)
        print "start execue", cmd
        cmd2 = '/usr/local/bin/cuckoo submit --url {}'.format(url.split()[0])
        child = pexpect.spawn(cmd2)
        fout = file(self.tmp_file, 'w')
        child.logfile = fout
        child.interact()
        """
        os.system(cmd)
        """
        time.sleep(2)
        open_tmp_file = open(self.tmp_file, 'rb+')
        read_tmp_file = open_tmp_file.read()
        open_tmp_file.close()

        find_status = r'([a-zA-Z]*)\:'
        status_pattern = re.compile(find_status)
        status_m = status_pattern.search(read_tmp_file)
    '''

    def start_cuckoo2(self,url,parent_dir):
        state1=""
        list_file_operation1=[]
        list_command_line1=[]
        refer_url1=""
        list_url_chain1=[]
        ek_name1=""
        set_cwd('/opt/cuckoo')
        db = Database()
        db.connect()
        id=db.add_url(url.split()[0])
        print "folder {} is running".format(id)
        while True:
            if str(db.guest_get_status(id))=="stopped":
                break
        print "folder {} is stopped".format(id)
	time.sleep(70)
	#subfolder = os.listdir("/opt/cuckoo/storage/analyses")
	#print subfolder
	
        state_analyse_=state_analyse(id,parent_dir)
        state1=state_analyse_.state_decide_single()
        list_file_operation1=state_analyse_.analyse_file_operation_single()
        list_command_line1=state_analyse_.analyse_command_line_single()
        refer_url1=state_analyse_.acquire_refer_url_single()
        list_url_chain1,ek_name1=state_analyse_.analyse_url_chain_single()
        campaign_name=state_analyse_.analyse_Campaign_single()
	    #print list_file_operation
        
        #print "Unexpected error:{}".format(sys.exc_info()[0])
        print " foler {} state is {}".format(id,state1)
        return id,state1,list_file_operation1,list_command_line1,refer_url1,list_url_chain1,ek_name1,campaign_name
        

    def start(self,file,parent_dir):
		#sys.path.append(parent_dir+'/util/')
        parent_dir_file=self.exchange_workspace(parent_dir)
        #file="/opt/exploitkit_automation/"+file
        file=os.path.join(parent_dir_file,'crawl_file',file)
        read_file = open(file,'rb')
        for line in read_file:
            state2=""
            list_file_operation2=[]
            list_command_line2=[]
            refer_url2=""
            list_url_chain2=[]
            ek_name2=""
            #config vpn
            vpn_to_use = None
            line_lenght = len(line.split())
            if line_lenght == 5:
                print "no country!"
                self.config_vpn('usa_-_los_angeles_-_3_udp')
            elif line_lenght == 6:
                country = line.split()[-1]
                self.config_vpn(country)
            else:
                print "check url!"
                continue
            url_to_use = line.split()[0]
            #EKName=line.split()[1]
            #use vpn
            #self.use_vpn(url_to_use)
            id,state2,list_file_operation2,list_command_line2,refer_url2,list_url_chain2,ek_name2,campaign_name=self.start_cuckoo2(url_to_use,parent_dir)
            
            print "begin to insert to databaset"
            try:
                operate_database_=operate_database(refer_url2,ek_name2,state2,id,list_file_operation2,list_command_line2,list_url_chain2,campaign_name)
                operate_database_.insert_to_db()
            except:
                print "Unexpected error:{}".format(sys.exc_info()[0])

    def exchange_workspace(self,parent_dir):
        os.chdir(parent_dir)
        parent_dir=os.getcwd()
        return parent_dir
            

def getYesterday(): 
    today=datetime.date.today() 
    oneday=datetime.timedelta(days=1) 
    yesterday=today-oneday  
    return yesterday.strftime("%Y%m%d")

def print_help():
    print "python start_cuckoo_via_vpn.py latest dst_path parent_dir"

if __name__ == '__main__':
    if len(sys.argv)!=4:
        print_help()
    else:
        """
        with open('config.json', 'rb') as fh:
            config = json.load(fh)
        start_cuckoo = StartCuckoo(config)
        """
	if sys.argv[1] == 'latest':
            date_str = getYesterday()
            file_name="wrs_"+date_str+"_extract_crawl.txt"
        else:
            file_name="wrs_"+sys.argv[1]+"_extract_crawl.txt"
       
        start_cuckoo = StartCuckoo()
        input_path = sys.argv[2]
        if not os.path.exists(input_path):
            os.makedirs(input_path)
            os.chmod(input_path, 0o777)
        start_cuckoo.result_root_path = input_path
        start_cuckoo.result_file_path = os.path.join(start_cuckoo.result_root_path,start_cuckoo.result_file_path)
        if not os.path.exists(start_cuckoo.result_file_path):
            os.mknod(start_cuckoo.result_file_path)
            os.chmod(start_cuckoo.result_file_path, 0o777)
        
        start_cuckoo.vpn_log_path = start_cuckoo.result_root_path + "vpn_log/"
        if not os.path.exists(start_cuckoo.vpn_log_path):
            os.makedirs(start_cuckoo.vpn_log_path)
            os.chmod(start_cuckoo.vpn_log_path, 0o777)
        parent_dir=sys.argv[3]
        start_cuckoo.start(file_name,parent_dir)

