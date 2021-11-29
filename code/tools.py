# -*- coding: utf-8 -*-
# @Time : 2020/7/17 10:59
# @Author : rodgerlu
# @Desc :
import uuid
import time
import json
import traceback
import os
import hashlib
from flask import request, Response
import subprocess
import pymysql
import datetime
import copy
from elasticsearch import Elasticsearch
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
import boto3
import requests


def conf_create():
    DB = {"user_db": {'host': 'localhost', 'port': 3306, 'password': 'root', 'db': 'user_info', "user": 'root'}}
    with open('../conf/conf.json', 'w', encoding='utf-8') as f:
        json.dump(DB, f)


def conf_load(db_name='user_db'):
    if not os.path.exists("../conf/conf.json"):
        conf_create()
    with open('../conf/conf.json', 'r', encoding='utf-8') as f:
        db = json.load(f)
        return db[db_name]


def get_pymysql(db_name='user_db'):
    config_dic = conf_load(db_name)
    config = {'host': config_dic['host'], 'port': config_dic['port'], 'password': config_dic['password'],
              'db': config_dic['db'], "user": config_dic['user'], 'charset': 'utf8'}
    conn = pymysql.connect(**config)
    cur = conn.cursor(pymysql.cursors.DictCursor)
    return conn, cur


# 使用uuid生成全球唯一标识id
def generate_id():
    id = uuid.uuid1()
    return str(id).lower().replace("-", "")


# 使用flask 给客户端发送回应
def response_data(data):
    result = {"status": 200, "data": data}
    return Response(json.dumps(result, ensure_ascii=False), mimetype="application/json")


def response_error(code, msg):
    result = {"status": code, "error": msg, "traceback:": traceback.format_exc()}
    return Response(json.dumps(result, ensure_ascii=False), mimetype="application/json")


# 获取文件的md5
def get_file_md5(file_path):
    if not os.path.isfile(file_path):
        return
    myhash = hashlib.md5()
    f = open(file_path, "rb")
    while True:
        b = f.read()
        if not b:
            break
        myhash.update(b)
    f.close()
    return myhash.hexdigest()


# 获取文件的大小字节
def get_file_size_bytes(file_path):
    try:
        file_size = os.path.getsize(file_path)
        return file_size
    except Exception as err:
        print(err)


# 获取文件的访问时间,创建时间,修改时间
def get_file_time(file_path):
    atime = os.path.getatime(file_path)
    ctime = os.path.getctime(file_path)
    mtime = os.path.getmtime(file_path)
    return atime, ctime, mtime


# 格式化时间戳
def fomat_timestamp(secs, schema="%Y-%m-%d %H:%M:%S"):
    localtime = time.localtime(secs)
    format_time = time.strftime(schema, localtime)
    return format_time


# 字符转时间戳
def to_timestamp(time_str, schema="%Y-%m-%d %H:%M:%S"):
    localtime = time.strptime(time_str, schema)
    timestamp = time.mktime(localtime)
    return int(timestamp)


# 文件是否存在
def file_is_exist(file_path):
    return os.path.isfile(file_path)


# 将错误信息保存至文件中
def log_error(msg, path):
    mess = "-" * 100 + str(datetime.datetime.now()) + "\n"
    msg = mess + msg
    with open(path, 'a', encoding='utf-8') as f:
        f.write(msg)


# 执行shell语句,并按行列表返回执行后的信息
def do_shell(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    result = copy.deepcopy(p.stdout.readlines())
    if p.stdin:
        p.stdin.close()
    if p.stdout:
        p.stdout.close()
    if p.stderr:
        p.stderr.close()
    try:
        p.kill()
    except OSError:
        pass
    finally:
        return result


# 生成备份路径
def generate_backup_path(file_name, version):
    return 's3://leyi-data-mining/publish-system/backup/' + str(file_name) + ".json." + str(version)


# 转化为str
def to_str(ob):
    if ob is None:
        return ob
    else:
        return str(ob)


#
def get_timestamp_from_gmt(str_time):
    format_time = time.strptime(str_time, "%a,%d%b%Y%H:%M:%S")
    return int(time.mktime(format_time))


# 获取路径文件列表
def get_file_list(path):
    if os.path.exists(path):
        file_list = [(os.path.join(path, _)) for _ in os.listdir(path) if os.path.isfile(os.path.join(path, _))]
        return file_list
    else:
        return []


# 截取起始标志字符
def get_val_from_str(line, beg_key, end_key):
    index_begin = line.find(beg_key)
    index_end = line.find(end_key, index_begin + 1)
    if index_begin == -1 or index_end == -1:
        return -1
    return line[index_begin + len(beg_key):index_end]


# 获取指定时间段内,指定间隔时间的每个date
def get_date_list(begin_time: str, end_time: str, interval: int, input_format="%Y%m%d%H%M%S",
                  output_format="%Y%m%d%H%M%S"):
    b_time = time.mktime(time.strptime(begin_time, input_format))
    e_time = time.mktime(time.strptime(end_time, input_format))
    date_set = set()
    while b_time < e_time:
        date_set.add(time.strftime(output_format, time.localtime(b_time)))
        b_time += interval
    date_set.add(time.strftime(output_format, time.localtime(e_time)))
    date_list = sorted(list(date_set), key=lambda s: int(s))
    return date_list


# 获取s3 md5 值
def get_s3_md5(path):
    s3md5 = ''
    s3_info_shell = 's3cmd info ' + path
    s3_info = do_shell(s3_info_shell)
    for info in s3_info:
        if 'MD5' in info:
            s3md5 = info.replace('\n', '').replace('MD5 sum:', '').replace(' ', '')
    return s3md5


# 获取s3 文件大小
def get_s3_size(path):
    s3size = 0
    s3_info_shell = 's3cmd info ' + path
    s3_info = do_shell(s3_info_shell)
    for info in s3_info:
        if 'File size:' in info:
            s3size = info.replace('\n', '').replace('File size:', '').replace(' ', '')
    return int(s3size)


# 获取s3 修改时间
def get_s3_mtime(path):
    s3mtime = 0
    s3_info_shell = 's3cmd info ' + path
    s3_info = do_shell(s3_info_shell)
    for info in s3_info:
        if 'Last mod' in info:
            str_time = info.replace('\n', '').replace('Last mod:', '').replace(' ', '').replace('GMT', '')
            s3mtime = get_timestamp_from_gmt(str_time)
    return s3mtime


# 连接远端机器执行shell
def do_shell_remote(host, command):
    shell = "ansible {} -m shell -a '{}'".format(host, command)
    p = subprocess.Popen(shell, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    result = copy.deepcopy(p.stdout.readlines())
    if p.stdin:
        p.stdin.close()
    if p.stdout:
        p.stdout.close()
    if p.stderr:
        p.stderr.close()
    try:
        p.kill()
    except OSError:
        pass
    finally:
        return result


# 复制文件到远程机器
def copy_file_remote(host, src, dest):
    shell = "ansible {} -m copy -a 'src={} dest={} force=yes'".format(host, src, dest)
    p = subprocess.Popen(shell, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    result = copy.deepcopy(p.stdout.readlines())
    if p.stdin:
        p.stdin.close()
    if p.stdout:
        p.stdout.close()
    if p.stderr:
        p.stderr.close()
    try:
        p.kill()
    except OSError:
        pass
    finally:
        return result


# 读取json文件
def read_json_file(path, encoding="utf-8"):
    return json.load(open(path, 'r', encoding=encoding))


# 写入json文件
def write_json_file(ob, path, encoding="utf-8"):
    with open(path, "w", encoding=encoding) as f:
        json.dump(ob, f, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        f.close()


def get_elasticsearch(name, hosts=None):
    if hosts is None:
        hosts = ["172.31.0.193:9200", "172.31.0.15:9200", "172.31.0.192:9200"]
    with open("../conf/elastic.conf.json", "r", encoding="utf-8") as f:
        info = json.load(f)[name]
        f.close()
    username = decry_string(info['username'])
    password = decry_string(info['password'])
    es = Elasticsearch(hosts=hosts, http_auth=(username, password))
    return es


# 加密字符串
def encry_string(string):
    hash_str = hashlib.new("md5", string.encode(encoding="utf-8")).hexdigest()
    encry_str = base64.b64encode(string.encode(encoding="utf-8")).decode() + hash_str
    encry_str = encry_str.replace("=", "2edaa9663e7f11ebb962d81265db4cac")
    return encry_str


# 解密字符串
def decry_string(string):
    string = string.replace("2edaa9663e7f11ebb962d81265db4cac", '=')
    index = string.rfind("=")
    string = string[:index + 1]
    return base64.b64decode(string.encode(encoding="utf-8")).decode()


# 发送邮件
def send_mail(receivers, title=None, content=None, file_list=[], sender="op@leyinetwork.com", password="Yunying123"):
    msg = MIMEMultipart()
    msg['Subject'] = Header(title, "utf-8")
    msg.attach(MIMEText(content, 'plain', 'utf-8'))
    for f in file_list:
        fh = MIMEText(open(f, 'rb').read(), 'base64', 'utf-8')
        fh["Content-Type"] = 'application/octet-stream'
        fh["Content-Disposition"] = 'attachment; filename=' + f.split("/")[-1]
        msg.attach(fh)
    msg['From'] = Header(sender, "utf-8")
    msg['To'] = Header(",".join(receivers), "utf-8")
    server = smtplib.SMTP_SSL("smtp.exmail.qq.com", 465)
    server.login(sender, password)
    server.sendmail(sender, receivers, msg.as_string())
    server.quit()


# 获取s3 client
def get_s3_client(aws_access_key_id=None, aws_secret_access_key=None, region=None):
    if aws_access_key_id is None:
        aws_access_key_id = "AKIAJTAPWNGELBAIQ3EA"
    if aws_secret_access_key is None:
        aws_secret_access_key = "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"
    if region is None:
        region = "us-east-1"
    client = boto3.client('s3', region_name=region, aws_access_key_id=aws_access_key_id,
                          aws_secret_access_key=aws_secret_access_key)
    return client


# 读取s3 文件
def read_s3_file(client, Bucket, Key):
    info = client.get_object(Bucket=Bucket, Key=Key)
    for line in info["Body"].iter_lines():
        line_str = line.decode(encoding="utf-8", errors="ignore")
        yield line_str


# 获取s3 session
def get_s3_session(aws_access_key_id=None, aws_secret_access_key=None, region=None):
    if aws_access_key_id is None:
        aws_access_key_id = "AKIAJTAPWNGELBAIQ3EA"
    if aws_secret_access_key is None:
        aws_secret_access_key = "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"
    if region is None:
        region = "us-east-1"
    session = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                    aws_secret_access_key=aws_secret_access_key, region_name=region)
    return session


# 读取s3列表
def get_s3_file_list(bucket_name, prefix=None, count=None, session=get_s3_session()):
    s3_list = []
    resource = session.resource('s3')
    if prefix is not None:
        for obj in resource.Bucket(bucket_name).objects.filter(Prefix=prefix):
            s3_path = "s3://" + obj.bucket_name + "/" + obj.key
            s3_list.append(s3_path)
        return s3_list
    elif count is not None:
        for obj in resource.Bucket(bucket_name).objects.limit(count=count):
            s3_path = "s3://" + obj.bucket_name + "/" + obj.key
            s3_list.append(s3_path)
        return s3_list
    else:
        for obj in resource.Bucket(bucket_name).objects.all():
            s3_path = "s3://" + obj.bucket_name + "/" + obj.key
            s3_list.append(s3_path)
        return s3_list


# boto3 读取s3 md5
def get_s3_md5_by_boto3(aws_access_key_id, aws_secret_access_key, region_name, Bucket, Key):
    # aws_access_key_id = "AKIAP3M5E74QM2FNBZWQ"
    # aws_secret_access_key = "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"
    # region_name = 'cn-north-1'
    s3_client = get_s3_client(aws_access_key_id, aws_secret_access_key, region_name)
    info = s3_client.get_object(Bucket=Bucket, Key=Key)
    if 'ETag' in info:
        s3_md5 = eval(info['ETag'])
    else:
        s3_md5 = ""
    return s3_md5


# 下载s3文件
def get_s3_file(aws_access_key_id, aws_secret_access_key, region_name, Bucket, Key, path):
    s3_client = get_s3_client(aws_access_key_id, aws_secret_access_key, region_name)
    with open(path, 'wb') as f:
        s3_client.download_fileobj(Bucket, Key, f)


# 上传s3文件
def upload_s3_file(aws_access_key_id, aws_secret_access_key, region_name, Bucket, Key, path):
    s3_client = get_s3_client(aws_access_key_id, aws_secret_access_key, region_name)
    s3_client.upload_file(Filename=path, Key=Key, Bucket=Bucket)


# 钉钉发送消息
def alarm_put(msg, atMobiles=[], isAtAll=False, access_token=None, msgtype="text", title='', picurl='', messageurl=''):
    if not access_token:
        access_token = "4972fd721179064b9ad9167e2ef70d8689cb3bc6b4b5f353821a6226201ee591"
    datas = {
        "msgtype": msgtype,
        "at": {
            "atMobiles": atMobiles,
            "isAtAll": isAtAll
        }
    }
    if msgtype == "text":
        datas[msgtype] = {"content": msg}
    elif msgtype == "link":
        datas[msgtype] = {"text": msg,
                          "title": title,
                          "picUrl": picurl,
                          "messageUrl": messageurl}
    elif msgtype == "markdown":
        datas[msgtype] = {"text": msg,
                          "title": title}
    else:
        msg = "has no this type"
        print(msg)
        return
    headers = {'content-type': "application/json"}
    datas = json.dumps(datas)
    r = requests.post("https://oapi.dingtalk.com/robot/send?access_token={0}".format(access_token), data=datas,
                      headers=headers)
    return json.loads(r.text)


# elk 时间str 转 int
def get_elk_timestamp(str):
    return int(time.mktime(time.strptime(str, "%Y-%m-%dT%H:%M:%S.%fZ")) * 1000)


# elk 时间int 转 str
def get_elk_str_time(timestamp):
    time_str = datetime.datetime.fromtimestamp(timestamp / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return time_str[:-3] + "Z"


# 输入天数获取 月 周 日 的开始结束时间
def get_time_section(time_type, date, return_type="str", return_schema="%Y%m%d"):
    """
        根据输入天数，获得包含该天的当年、月、周、天起始时间
        :param time_type: 获取时间类型 string eg:day
        :param date: 需要包含的日期  string  eg: 20210111
        :param return_schema: 需要输出的字符格式，默认为年月日 eg: 20210111
        :param return_type: 需要输出的类型，str为字符串，timestamp为时间戳int值
        :return start_date: elk开始时间 string eg: 20210111
        :return end_date: elk结束时间 string eg: 20210111
    """
    if time_type == "day":
        start_timestamp = to_timestamp(date + "000000", "%Y%m%d%H%M%S")
        end_timestamp = to_timestamp(date + "235959", "%Y%m%d%H%M%S")
        start_date = fomat_timestamp(start_timestamp, schema=return_schema)
        end_date = fomat_timestamp(end_timestamp, schema=return_schema)
    elif time_type == "week":
        week = int(time.strftime("%w", time.localtime(time.mktime(time.strptime(date, "%Y%m%d")))))
        if week == 0:
            week = 7
        start_timestamp = to_timestamp(date, "%Y%m%d") - (week - 1) * 24 * 60 * 60
        end_timestamp = start_timestamp + 7 * 24 * 60 * 60 - 1
        start_date = fomat_timestamp(start_timestamp, schema=return_schema)
        end_date = fomat_timestamp(end_timestamp, schema=return_schema)
    elif time_type == "month":
        start_timestamp = to_timestamp(date[:6] + "01000000", "%Y%m%d%H%M%S")
        start_date = fomat_timestamp(start_timestamp, schema=return_schema)
        end_timestamp = to_timestamp(date[:6] + "28", "%Y%m%d") + 4 * 24 * 60 * 60
        e_date = fomat_timestamp(end_timestamp, "%Y%m01000000")
        end_timestamp = to_timestamp(e_date, "%Y%m%d%H%M%S") - 1
        end_date = fomat_timestamp(end_timestamp, schema=return_schema)
    elif time_type == "year":
        start_timestamp = to_timestamp(date[:4] + "0101000000", "%Y%m%d%H%M%S")
        start_date = fomat_timestamp(start_timestamp, schema=return_schema)
        end_timestamp = to_timestamp(date[:4] + "1228", "%Y%m%d") + 4 * 24 * 60 * 60
        e_date = fomat_timestamp(end_timestamp, "%Y%m01000000")
        end_timestamp = to_timestamp(e_date, "%Y%m%d%H%M%S") - 1
        end_date = fomat_timestamp(end_timestamp, schema=return_schema)
    else:
        raise Exception("time_type 不存在")
    if return_type == "timestamp":
        return start_timestamp, end_timestamp
    elif return_type == "str":
        return start_date, end_date
    else:
        raise Exception("return_type 不存在")


# http get请求
def http_get(url, **params):
    r = requests.get(url=url, params=params)
    return r


# http post请求
def http_post(url, **params):
    r = requests.post(url=url, data=json.dumps(params))
    return r
