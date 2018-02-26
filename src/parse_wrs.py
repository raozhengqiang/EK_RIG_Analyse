import os
import sys
import ast
import time
import re
import yara
import socket

class WRSParser(object):
    def __init__(self, src_file):
        self.src_file_ = src_file
        self.result_file_ = None
        self.tmp_file = 'tmp.txt'
        self.ek_file_ = 'C:\Users\zhengqiang_rao\Desktop\cuckoo\ExploitKit.yar'
        self.campaign_file_ = 'C:\Users\zhengqiang_rao\Desktop\cuckoo\Campaign.yar'
        self.interest_keys_ = ['rule_id', 'di', 'ho', 'i', 'c', 'li', 'x__TMUF_REFERER_RAW', 'ra','REFERER_ho']
        self.ek_rule_ = self.generate_rule(self.ek_file_)
        self.campaign_rule_ = self.generate_rule(self.campaign_file_)
        self.data_format_ = None

    def generate_result_file(self,FILE):
        parent_dir,file_name_suffix = os.path.split(FILE)
        file_name, suffix = os.path.splitext(file_name_suffix)
        result_file_name = '{}_{}{}'.format(file_name,'extract',suffix)
        result_file_path = os.path.join(parent_dir,result_file_name)
        return result_file_path

    def save_to_file(self, result_list):
        fh = open(self.result_file_, 'w')
        result = "Time\tEK Name\tWRS EKName\tFull URL\tHost\tReferer URL\tCampaign Name\tWRS Rating\tHost IP\tClinet IP\tClient Country\tProduct\n"
        fh.write(result)
        for result_dict in result_list:
            result = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" % (
                result_dict['t'], result_dict['rule_id_sa'], result_dict['rule_id'],
                result_dict['full_url'], result_dict['ho'], result_dict['x__TMUF_REFERER_RAW'],
                result_dict['campaign_name'],result_dict['ra'],result_dict['di'],
                result_dict['i'], result_dict['c'], result_dict['li'],)
            fh.write(result)
        fh.close()

    def process_dict(self, src_dict):
        result_dict = {}
        # process common key
        for each_key in self.interest_keys_:
            if each_key not in src_dict:
                src_dict[each_key] = '-'
            result_dict[each_key] = src_dict[each_key]

        # process timestr
        result_dict['t'] = self.convert_time_format(src_dict['t'])
        # result_dict['t'] = src_dict['t']

        # get full url
        full_url = self.get_full_url(src_dict['sch'], src_dict['ho'], src_dict['po'], src_dict['pa'])
        result_dict['full_url'] = full_url

        # match ek pattern
        ek_name = self.ek_match(full_url)
        result_dict['rule_id_sa'] = ek_name


        if ek_name is not 'UnknownExploit':
            refer_content = result_dict['x__TMUF_REFERER_RAW']
            result_dict['campaign_name'] = self.refer_match(refer_content)
        else:
            result_dict['campaign_name'] = '-'

        # return result dict
        return result_dict

    def get_full_url(self, protocol, domain, port, path):
        if protocol == "":
            protocol = 'HTTP'
        result = protocol.lower() + "://" + domain
        if port != '80':
            result = result + ":" + port
        result = result + path
        return result

    def convert_time_format(self, timestamp_str):
        x = time.localtime(int(timestamp_str) - 28800)
        return time.strftime('%m/%d/%Y:%H:%M', x)

    def generate_rule(self,path):
        return yara.compile(path)

    def ek_match(self, url):
        print "------------{}".format(url)
        print "***********{}".format(self.ek_rule_)
        matchs = self.ek_rule_.match(data=url)
        if matchs:
            ek_lenght = len(matchs)
            print matchs
            ek_result = matchs[0]
            if ek_lenght > 1:
                for i in range(1,ek_lenght):
                    ek_result += ';'
                    ek_result += matchs[i]
            return ek_result
        return 'UnknownExploit'

    def refer_match(self,Refer):
        matchs = self.campaign_rule_.match(data=Refer)
        if matchs:
            refer_length = len(matchs)
            refer_result = str(matchs[0])
            if refer_length > 1:
                for i in range(1, refer_length):
                    refer_result += ';'
                    refer_result += str(matchs[i])
            return refer_result
        return '-'

    def judge_which_format(self, line):
        if "rule_id" in line:
            return "wrs"
        else:
            return "lumberjack"

    def fix_null(self,input_line):
        output_line = None
        null_pattern = re.compile("\"REFERER_ho\": null")
        output_line = null_pattern.sub("\"REFERER_ho\": \"null\"",input_line)
        return output_line

    def convert_to_dict(self, line):
        if not self.data_format_:
            self.data_format_ = self.judge_which_format(line)

        if self.data_format_ == "wrs":
            try:
                result_dict = ast.literal_eval(self.fix_null(line))
            except:
                print self.fix_null(line)
        elif self.data_format_ == "lumberjack":
            result_dict = {}
            data_list = line.split('\t')
            for each_data in data_list:
                equal_sign_index = each_data.find('=')
                key = each_data[:equal_sign_index]
                value = each_data[equal_sign_index + 1:]
                result_dict[key] = value
        return result_dict

    def process_file(self,file_path):
        self.result_file_ = self.generate_result_file(file_path)
        result_list = []
        for line in open(file_path):
            line = line.strip()
            temp_dict = self.convert_to_dict(line)
            result_dict = self.process_dict(temp_dict)
            result_list.append(result_dict)
        self.save_to_file(result_list)

    def start_extract(self):
        if os.path.isfile(self.src_file_):
            self.process_file(self.src_file_)
            return self.result_file_

        if os.path.isdir(self.src_file_):
            for root, dirs, files in os.walk(self.src_file_):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    self.process_file(file_path)
def print_help():
    print """
python parse_wrs.py file/dir
    """

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_help()
    else:
        file_parser = WRSParser(sys.argv[1])
        file_parser.start_extract()

