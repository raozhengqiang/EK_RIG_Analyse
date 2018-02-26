import pymysql
import os
import datetime
import sys

class operate_database(object):
    def __init__(self,url,name,state,id,list_file_operation,list_command_line,list_url_chain,campaign_name):
        self._url=url
        self._name=name
        self._state=state
        self._id=id
        self._list_file_operation=list_file_operation
        self._list_command_line=list_command_line
        self._list_url_chain=list_url_chain
        self._campaign_name=campaign_name

    def insert_to_db(self):
        obj={}
        conn=pymysql.connect(host='10.5.32.24',user='root',password='123456',db='refer_url_data',charset='utf8')
        cursor=conn.cursor()
        cursor.execute("set names utf8")
        obj=self.make_obj(obj)
        str_file_operation=""
        str_command_line=""
        str_url_chain=""
        for i in range(0,len(self._list_file_operation)):
            if i!=len(self._list_file_operation)-1:
                str_file_operation=str_file_operation+self._list_file_operation[i]+"\n"
            else:
                str_file_operation=str_file_operation+self._list_file_operation[i]
        for i in range(0,len(self._list_command_line)):
            if i!=len(self._list_command_line):
                str_command_line=str_command_line+"command_line:"+self._list_command_line[i]+"\n"
            else:
                str_command_line=str_command_line+"command_line:"+self._list_command_line[i]
        for i in range(0,len(self._list_url_chain)):
            if i!=len(self._list_url_chain):
                str_url_chain=str_url_chain+"same_host_url:"+self._list_url_chain[i]+"\n"
            else:
                str_url_chain=str_url_chain+"same_host_url:"+self._list_url_chain[i]
        sqlStr='insert into refer_url_data (Date,Sourcing,url,EKName,State,Cuckoo_content,file_operation,processtree_ie_command_line,url_chain,Campaign_Name) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
	       
	try:
            cursor.execute(sqlStr,(obj['Date'],obj['Sourcing'],obj['url'],obj['EKName'],obj['State'],obj['Cuckoo_content'],str_file_operation,str_command_line,str_url_chain,obj['Campaign_Name']))
            conn.commit()
        except:
            conn.rollback()
            print "Unexpected error:{}".format(sys.exc_info()[0])


    def make_obj(self,obj):
        obj['Date']=datetime.datetime.now().strftime("%Y-%m-%d")
        obj['Sourcing']="WRS"
        obj['url']=self._url
        obj['EKName']=self._name
        obj['State']=self._state
        obj['Cuckoo_content']="/opt/cuckoo/storage/analyses/"+str(self._id)
        obj['Campaign_Name']=self._campaign_name
        return obj
        
        
        

        
    
