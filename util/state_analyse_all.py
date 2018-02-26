import json
import os
import sys
import yara
import ConfigParser
class state_analyse_all(object):
    
    def __init__(self,setting):
        self.state=""
        self._setting_=setting
            
    def load_Font(self):
        #parent_path=r"E:\data\13\reports"
        parent_path="/opt/cuckoo/storage/analyses"

        f=open(os.path.join(parent_path,str(self._id_),"reports","report.json"))
        setting=json.load(f)
        return setting

    #analyse state
    def state_decide_single(self):
        
        #length=len(setting['network']['http'])
        #http=setting['network']['http']
        #print len
        
        tree_root=self._setting_['behavior']['processtree'][1]['children']
        if len(tree_root)==0:
            return 'exploitfail'
        else:
            tree_branch=tree_root[0]
            if str(tree_branch["process_name"])=='iexplore.exe':
                tree_branch=tree_branch['children']
                if len(tree_branch)==0:
                    return 'exploitfail'
                else:
                    tree_branch=tree_branch[0]
                    if str(tree_branch["process_name"])=='cmd.exe':
                        tree_branch=tree_branch['children']
                        
                        if len(tree_branch)==0:
                            return 'exploitfail'
                        else:
                            tree_branch=tree_branch[0]
                            if str(tree_branch["process_name"])=='wscript.exe':
                               
                                tree_branch=tree_branch['children']
                                #return 'exploitsuccess'
                                if len(tree_branch)==0:
                                    return 'exploitsuccess'
                                else:
                                    return self.get_step(tree_branch)
            
        return 'exploitfail'

    #analyse file_operation
    def analyse_file_operation_single(self):
        #setting=self.load_Font()
        list_file_operation=[]
        list_type=[]
        
        cf = ConfigParser.ConfigParser()
       
        type_dir='type.conf'
        
        cf.read(type_dir)
        opts=cf.options("type")
        summary=self._setting_['behavior']['summary']
        if self._setting_.has_key('dropped'):
            
            dropped=self._setting_['dropped']
            
            
            for i in range(0,len(dropped)):
                #print i
                try:
                    filepath=str(dropped[i]['filepath'])
                    size=str(dropped[i]['size'])
                    sha256=str(dropped[i]['sha256'])
            
                    for j in range(0,len(opts)):
                        if str(cf.get("type",opts[j])) in filepath:
                            list_file_operation.append("file_created:"+filepath+"  "+size+"  "+sha256)
                except:
                    print "Unexpected error:{}".format(sys.exc_info()[0])
                    
        

        if summary.has_key('file_deleted'):
            file_deleted_list=summary['file_deleted']
            len_file_deleted_list=len(file_deleted_list)
            for i in range(0,len_file_deleted_list):
                for j in range(0,len(opts)):
                    if str(cf.get("type",opts[j])) in str(file_deleted_list[i]):
                        list_file_operation.append("file_deleted:"+str(file_deleted_list[i]))
        
        return list_file_operation


    #analyse ie command line
    def analyse_command_line_single(self):
        list_command_line=[]
        
        tree_root=self._setting_['behavior']['processtree'][1]
        list_command_line.append(str(tree_root['command_line']))
        tree_root=tree_root['children']
        list_command_line=self.get_step_comannd_line(tree_root,list_command_line)
        #for i in range(0,len(list_command_line)):
            #print list_command_line[i]+"\n"
        return list_command_line

    #acquire refer_url through reports.json
    def acquire_refer_url_single(self):
        
        command_line=str(self._setting_['behavior']['processtree'][1]['command_line'])
        refer_url=command_line.split()[-1]
        return refer_url

    #analyse url_chain
    def analyse_url_chain_single(self):
        
        host=""
        list_url_chain=[]
        list_http=self._setting_['network']['http']
        len_http=len(list_http)
        path='ExploitKit.yar'
        ek_rule_ = self.generate_rule(path)
        for i in range(0,len_http):
            uri=str(list_http[i]['uri'])
            ek_name=self.ek_match(uri,ek_rule_)
            if str(ek_name)!='UnknownExploit':
                host=str(list_http[i]['host'])
                num_ek_name=i
                #print num_ek_name
                #print ek_name
                #print host
                break
            else:
                if i==len_http-1:
                    ek_name=""
                    #print ek_name
        for i in range(0,len_http):
            if str(list_http[i]['host'])==host:
                list_url_chain.append(str(list_http[i]['uri']))
        #for i in range(0,len(list_url_chain)):
            #print list_url_chain[i]+"\n"
            
        #print "------------------------"
        return list_url_chain,str(ek_name)

    def generate_rule(self,path):
        return yara.compile(path)

    def ek_match(self,url,ek_rule_):
        #print "------------{}".format(url)
        #print "***********{}".format(ek_rule_)
        matchs =ek_rule_.match(data=url)
        #print matchs
        if matchs:
            ek_lenght = len(matchs)
            #print ek_lenght
            #print matchs
            ek_result = matchs[0]
            if ek_lenght > 1:
                for i in range(1,ek_lenght):
                    ek_result += ';'
                    ek_result += matchs[i]
            #print ek_result
            return ek_result
        return 'UnknownExploit'



    def get_step_comannd_line(self,tree,list_command_line):
        if(len(tree)==0):
            return list_command_line
        else:
            tree=tree[0]
            list_command_line.append(str(tree['command_line']))
            tree=tree['children']
            list_command_line=self.get_step_comannd_line(tree,list_command_line)
            return list_command_line
            
            



        


        

    def get_step(self,tree):
        now_state=''
        if(len(tree)==0):
            now_state='exploitsuccess'
            return now_state
        else:
            tree=tree[0]
            if str(tree['command_line'])[-4:]=='.exe':
                now_state='runpayload'
                return now_state
            tree=tree['children']
            now_state=self.get_step(tree)
            return now_state

    #analyse Campaign name
    def analyse_Campaign_single(self):
        
        tree_root=self._setting_['behavior']['processtree'][1]
        url=str(tree_root['command_line']).split('"')[-1]
        url=url[1:]
        #print url
        
        #cf = ConfigParser.ConfigParser()
        #os.chdir(self._parent_dir_)
        #parent_dir=os.getcwd()
        #path=parent_dir+'/conf_yar'+'/Campaign.yar'
        #ek_rule_ = self.generate_rule(path)
        
        path='Campaign.yar'
        compaign_rule_ = self.generate_rule(path)
        campaign_name=self.compaign_match(url,compaign_rule_)
        return campaign_name
        

    def compaign_match(self,Refer,compaign_rule_):
        matchs = compaign_rule_.match(data=Refer)
        if matchs:
            refer_length = len(matchs)
            refer_result = str(matchs[0])
            if refer_length > 1:
                for i in range(1, refer_length):
                    refer_result += ';'
                    refer_result += str(matchs[i])
            return refer_result
        return ''
            
    

if __name__=="__main__":
    if len(sys.argv)!=2:
        print_help()
    else:
        folder_path=sys.argv[1]
        s=state_analyse()
        s.search_all_file(folder_path)
        
#s=state_analyse()
#print s.state_decide()
#folder_path=r"E:\data"
#s.search_all_file(folder_path)
