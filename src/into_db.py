import json
import os,sys

sys.path.append("/opt/exploitkit_automation/util/")

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
from state_analyse_all import state_analyse_all
import time
class StartDB():
    def start_cuckoo2(self,setting):
        
        state_analyse_=state_analyse_all(setting)
        state=state_analyse_.state_decide_single()
        print state
        list_file_operation=state_analyse_.analyse_file_operation_single()
        list_command_line=state_analyse_.analyse_command_line_single()
        refer_url=state_analyse_.acquire_refer_url_single()
        list_url_chain,ek_name=state_analyse_.analyse_url_chain_single()
        campaign_name=state_analyse_.analyse_Campaign_single()
	#print list_file_operation
        
        print " foler {} state is {}".format(id,state)
        return state,list_file_operation,list_command_line,refer_url,list_url_chain,ek_name,campaign_name
        

    def start(self,folder_path):
        subfolder = os.listdir(folder_path)
        #for root,dirs,files in os.walk(folder_path):
            #print root
        len_subfolder=len(subfolder)
        for i in range(0,len_subfolder):
            if(subfolder[i].isdigit()):
                parent_path=os.path.join(folder_path,subfolder[i],"reports")
                print parent_path
                f=open(os.path.join(parent_path,"report.json"))
                setting=json.load(f)
        
                state,list_file_operation,list_command_line,refer_url,list_url_chain,ek_name,campaign_name=self.start_cuckoo2(setting)
                id=subfolder[i]
                print "begin to insert to databaset"
                try:
                    operate_database_=operate_database(refer_url,ek_name,state,id,list_file_operation,list_command_line,list_url_chain,campaign_name)
                    operate_database_.insert_to_db()
                except:
                    print "Unexpected error:{}".format(sys.exc_info()[0])
            



def print_help():
    print "python into db have no direction"

if __name__=="__main__":
    if len(sys.argv)!=2:
        print_help()
    else:
        folder_path=sys.argv[1]
        s=StartDB()
        s.start(folder_path)

