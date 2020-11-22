from django.http import HttpResponse
from django.db import connection
import pandas as pd
import time, datetime
import json
import math
import networkx as nx
import matplotlib.pyplot as plt
from vcs_django.settings import BASE_DIR
import random


def test(request):
    Data = {}
    return HttpResponse(json.dumps(Data), content_type='application/json')

def getPointEdgeByTime(request):
    params = json.loads(request.body)
    # malware_type_list = params['malwareType']
    # malware_subtype_list = params['malwareSubtype']
    begintime_str = params['beginTime']
    endTime_str = params['endTime']
    begin_date = datetime.datetime.strptime(begintime_str, '%Y-%m-%d %H:%M:%S')
    end_date = datetime.datetime.strptime(endTime_str, '%Y-%m-%d %H:%M:%S')
    begin_timestamp = int(time.mktime(begin_date.timetuple()))
    end_timestamp = int(time.mktime(end_date.timetuple()))

    # begintime_str = "2017-12-14 00:00:00"
    # endTime_str = "2017-12-15 00:00:00"
    # begin_date = datetime.datetime.strptime(begintime_str, '%Y-%m-%d %H:%M:%S')
    # end_date = datetime.datetime.strptime(endTime_str, '%Y-%m-%d %H:%M:%S')
    # begin_timestamp = int(time.mktime(begin_date.timetuple()))
    # end_timestamp = int(time.mktime(end_date.timetuple()))

    # # # 文件过滤
    # malware_type_list = ['网站后门', '恶意进程', '恶意脚本']  #
    # malware_subtype_list = ['WEBSHELL', '恶意脚本文件']
    # malware_type_list = tuple(malware_type_list)

    # 这里按malware_md5聚合
    cursor = connection.cursor()
    cursor.execute("select malware_md5, uuid AS ESC_ID, AS_ID, VPC_ID, Region_ID, malware_type "
                   "from malware_base_info AS a LEFT JOIN user_netstate_info AS b ON a.uuid=b.ECS_ID "
                   "where UNIX_TIMESTAMP(first_time) > '{0}' AND UNIX_TIMESTAMP(first_time) < '{1}' group by malware_md5".format(begin_timestamp, end_timestamp))

    desc = cursor.description
    alldata = cursor.fetchall()
    data = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    nodes = []
    for d in data:
        nodes.append({
            'id': d['malware_md5'],
            'user': 'Admin',
            'description': 'point',
            'file_type': d['malware_type'],
            'ecsId': d['ESC_ID'],
            'asId': d['AS_ID'],
            'vpcId': d['VPC_ID'],
            'regionId': d['Region_ID']
        })

    edge_list = []
    # 随机生成200000条边
    edge_list_set = set()  # 不重复
    count_edge = 0
    if len(data) > 1:
        while count_edge < len(data) / 2:
            x = random.randint(0, len(data) - 1)
            y = random.randint(0, len(data) - 1)
            edge_list_set.add((data[x]['malware_md5'], data[y]['malware_md5']))
            count_edge += 1

    for edge in edge_list_set:
        edge_list.append({'source': edge[0], 'target': edge[1]})

    Data = {
        'nodes': nodes,
        'links': edge_list
    }

    return HttpResponse(json.dumps(Data), content_type='application/json')


# 获取基本信息，不随时间变化
def get_base_info(request):
    # 获取恶意文件数量(先按出现次数来计算)
    # cursor = connection.cursor()
    # cursor.execute("select count(*) AS malwareNumber, "
    #                "SUM(CASE malware_type WHEN 'WEBSHELL' Then 1 ELSE 0 END) AS webshellNumber, "
    #                "SUM(CASE malware_type WHEN '被污染的基础软件' Then 1 ELSE 0 END) AS biNumber, "
    #                "SUM(CASE malware_type WHEN '恶意脚本文件' Then 1 ELSE 0 END) AS scriptNumber from malware_base_info")
    # desc = cursor.description
    # alldata = cursor.fetchall()
    # fileNumber = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    # t0 = time.time()        # 计时
    # 修改 获取实际的文件数量 而不是出现次数
    cursor = connection.cursor()

    # 先group by file_md5？
    cursor.execute("select count(*) AS malwareNumber, "
                   "SUM(CASE file_type WHEN 'WEBSHELL' Then 1 ELSE 0 END) AS webshellNumber, "
                   "SUM(CASE file_type WHEN 'BIN' Then 1 ELSE 0 END) AS biNumber, "
                   "SUM(CASE file_type WHEN 'SCRIPT' Then 1 ELSE 0 END) AS scriptNumber from "
                   "(select file_type from malware_base_info group by malware_md5) t")
    desc = cursor.description
    alldata = cursor.fetchall()
    fileNumber = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    # 获取ecs，as，vpc，region数量
    cursor.execute("select count(DISTINCT ECS_ID) AS ecsNumber, "
                   "count(DISTINCT AS_ID) AS asNumber, "
                   "      count(DISTINCT VPC_ID) AS vpcNumber, "
                   "count(DISTINCT Region_ID) AS regionNumber from user_netstate_info")

    desc = cursor.description
    alldata = cursor.fetchall()
    engines_data = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    Data = {
        'username': 'Admin',
        'engines': {
            'regionNumber': engines_data[0]['regionNumber'],
            'vpcNumber': engines_data[0]['vpcNumber'],
            'asNumber': engines_data[0]['asNumber'],
            'ecsNumber': engines_data[0]['ecsNumber'],
        },
        'files': {
            'malwareNumber': fileNumber[0]['malwareNumber'],
            'webshellNumber': int(str(fileNumber[0]['webshellNumber'])),
            'biNumber': int(str(fileNumber[0]['biNumber'])),
            'scriptNumber': int(str(fileNumber[0]['scriptNumber'])),
        }
    }

    # t1 = time.time()
    # print(t1 - t0, "seconds process time")
    # print(Data)
    return HttpResponse(json.dumps(Data), content_type='application/json')


# 获取基本信息，总的态势值
def get_base_info_time_series(request):
    # 建议加一个过滤按钮
    # 获取malware_type_list、malware_subtype_list参数
    # params = json.loads(request.body)
    # malware_type_list = params['malwareType']
    # malware_subtype_list = params['malwareSubtype']

    # t0 = time.time()        # 计时

    # 文件过滤
    malware_type_list = ['网站后门']
    malware_subtype_list = ['WEBSHELL', '恶意脚本文件']

    # 不定参数，生成where语句
    where_str = ''
    if malware_type_list != [] or malware_subtype_list != []:
        where_str = 'where '
        is_first = True  # 是否为开头
        is_second = True
        for i in malware_type_list:
            if is_first:
                where_str = where_str + "malware_class in (\'" + str(i) + "\' "
                is_first = False
            else:
                where_str = where_str + ", \'" + str(i) + "\' "

        if not is_first:
            where_str += ")"
        for i in malware_subtype_list:
            if is_first:
                where_str = where_str + "malware_type in (\'" + str(i) + "\' "
                is_first = False
                is_second = False
            elif is_second:
                where_str = where_str + " and malware_type in (\'" + str(i) + "\' "
                is_second = False
            else:
                where_str = where_str + ", \'" + str(i) + "\' "
        if not is_second:
            where_str += ")"

    # # 按小时聚合
    # cursor = connection.cursor()
    # cursor.execute("select concat(DATE_FORMAT(first_time, '%Y-%m-%d %H'),':00:00') as time,"
    #                "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue "
    #                "from malware_base_info " + where_str + "group by DATE_FORMAT(first_time, '%Y-%m-%d %H')")

    # 按天聚合
    cursor = connection.cursor()
    cursor.execute("select concat(DATE_FORMAT(first_time, '%Y-%m-%d '),'00:00:00') as time,"
                   "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue "
                   "from malware_base_info " + where_str + " group by DATE_FORMAT(first_time, '%Y-%m-%d')")

    desc = cursor.description
    alldata = cursor.fetchall()
    data = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    # 处理为接口格式
    Data = []
    # begin_timestamp = begin_date
    for i in data:
        if i['time'] != '0000-00-00 00:00:00':
            Data.append({
                'timestamp': i['time'],
                'levelValue': int(i['levelValue'])
            })

    Data = sorted(Data, key=lambda x: x['timestamp'])

    # print(Data)
    # t1 = time.time()  # 计时
    # print(t1 - t0, "seconds process time")
    return HttpResponse(json.dumps(Data), content_type='application/json')


def get_ECS_group(request):
    # 建议加一个过滤按钮
    # 获取malware_type_list、malware_subtype_list参数
    params = json.loads(request.body)
    malware_type_list = params['malwareType']
    malware_subtype_list = params['malwareSubtype']

    # 文件过滤
    # malware_type_list = ['网站后门', '恶意进程']
    # malware_subtype_list = ['WEBSHELL', '恶意脚本文件']

    # 不定参数，生成where语句
    # 不定参数，生成where语句
    where_str = ''
    if malware_type_list != [] or malware_subtype_list != []:
        where_str = 'where '
        is_first = True  # 是否为开头
        is_second = True
        for i in malware_type_list:
            if is_first:
                where_str = where_str + "malware_class in (\'" + str(i) + "\' "
                is_first = False
            else:
                where_str = where_str + ", \'" + str(i) + "\' "

        if not is_first:
            where_str += ")"
        for i in malware_subtype_list:
            if is_first:
                where_str = where_str + "malware_type in (\'" + str(i) + "\' "
                is_first = False
                is_second = False
            elif is_second:
                where_str = where_str + " and malware_type in (\'" + str(i) + "\' "
                is_second = False
            else:
                where_str = where_str + ", \'" + str(i) + "\' "
        if not is_second:
            where_str += ")"

    # 这里按ESC_ID聚合

    cursor = connection.cursor()
    cursor.execute("select uuid AS ESC_ID, AS_ID, VPC_ID, Region_ID, "
                   "count(*) AS malwareNumber,"
                   "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue,"
                   "sum(case when malware_type='WEBSHELL'then 1 else 0 end) as webshell, "
                   "sum(case when malware_type='DDOS木马' then 1 else 0 end) as DDOS木马,"
                   "sum(case when malware_type='被污染的基础软件' then 1 else 0 end) as 被污染的基础软件,"
                   "sum(case when malware_type='恶意程序' then 1 else 0 end) as 恶意程序,"
                   "sum(case when malware_type='恶意脚本文件' then 1 else 0 end) as 恶意脚本文件,"
                   "sum(case when malware_type='感染型病毒' then 1 else 0 end) as 感染型病毒,"
                   "sum(case when malware_type='黑客工具' then 1 else 0 end) as 黑客工具,"
                   "sum(case when malware_type='后门程序' then 1 else 0 end) as 后门程序,"
                   "sum(case when malware_type='勒索病毒' then 1 else 0 end) as 勒索病毒,"
                   "sum(case when malware_type='漏洞利用程序' then 1 else 0 end) as 漏洞利用程序,"
                   "sum(case when malware_type='木马程序' then 1 else 0 end) as 木马程序,"
                   "sum(case when malware_type='蠕虫病毒' then 1 else 0 end) as 蠕虫病毒,"
                   "sum(case when malware_type='挖矿程序' then 1 else 0 end) as 挖矿程序,"
                   "sum(case when malware_type='自变异木马' then 1 else 0 end) as 自变异木马 "
                   "from malware_base_info AS a LEFT JOIN user_netstate_info AS b ON a.uuid=b.ECS_ID " + where_str + " group by uuid")

    desc = cursor.description
    alldata = cursor.fetchall()
    data = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    if data == []:
        Data = {}
        return HttpResponse(json.dumps(Data), content_type='application/json')

    # 态势值对应的 danger | warn | safe

    # 先求得态势值10% 60%的值
    levelValue = []  # 保存态势值的数值
    for d in data:
        levelValue.append(int(d['levelValue']))
    levelValueSort = levelValue
    levelValueSort = sorted(levelValueSort)
    point90 = levelValueSort[math.floor(len(levelValueSort) / 10 * 9)]
    point40 = levelValueSort[math.floor(len(levelValueSort) / 10 * 4)]
    point97 = levelValueSort[math.floor(len(levelValueSort) / 10 * 9.7)]
    levelValueInfo = []  # 保存态势值的颜色
    isHighLight = []  # 保存ecs是否高危
    for l in levelValue:
        if l < point40:
            levelValueInfo.append('safe')
        elif l >= point40 and l < point90:
            levelValueInfo.append('warn')
        else:
            levelValueInfo.append('danger')

        if l > point97:
            isHighLight.append(True)
        else:
            isHighLight.append(False)

    # print(levelValueInfo)

    # 处理一下阈值 9 和 64  小于9不显示圆形 大于64显示file_info
    radius = []
    for d in data:
        malwareNumber = d['malwareNumber']
        if malwareNumber < 9:
            radius.append(0)
        elif malwareNumber >= 9 and malwareNumber <= 64:
            radius.append((math.sqrt(malwareNumber) - 3) / 5 * 10)
        else:
            radius.append(-1)

    # webshell, DDOS木马,被污染的基础软件,恶意程序,恶意脚本文件,感染型病毒,黑客工具,后门程序,勒索病毒,漏洞利用程序,木马程序,蠕虫病毒,挖矿程序,自变异木马

    # 处理文件信息
    file_info_count = 0
    file_info = []
    file_info_number = []
    for d in data:
        file_info.append({})
        file_info_number.append({})
        all_file_number = d['malwareNumber']
        if int(d['webshell']) != 0:
            file_info_number[file_info_count]['webshell'] = int(d['webshell'])
            file_info[file_info_count]['webshell'] = int(d['webshell']) / all_file_number
        if int(d['DDOS木马']) != 0:
            file_info_number[file_info_count]['DDOS木马'] = int(d['DDOS木马'])
            file_info[file_info_count]['DDOS木马'] = int(d['DDOS木马']) / all_file_number
        if int(d['被污染的基础软件']) != 0:
            file_info_number[file_info_count]['被污染的基础软件'] = int(d['被污染的基础软件'])
            file_info[file_info_count]['被污染的基础软件'] = int(d['被污染的基础软件']) / all_file_number
        if int(d['恶意程序']) != 0:
            file_info_number[file_info_count]['恶意程序'] = int(d['恶意程序'])
            file_info[file_info_count]['恶意程序'] = int(d['恶意程序']) / all_file_number
        if int(d['恶意脚本文件']) != 0:
            file_info_number[file_info_count]['恶意脚本文件'] = int(d['恶意脚本文件'])
            file_info[file_info_count]['恶意脚本文件'] = int(d['恶意脚本文件']) / all_file_number
        if int(d['感染型病毒']) != 0:
            file_info_number[file_info_count]['感染型病毒'] = int(d['感染型病毒'])
            file_info[file_info_count]['感染型病毒'] = int(d['感染型病毒']) / all_file_number
        if int(d['黑客工具']) != 0:
            file_info_number[file_info_count]['黑客工具'] = int(d['黑客工具'])
            file_info[file_info_count]['黑客工具'] = int(d['黑客工具']) / all_file_number
        if int(d['后门程序']) != 0:
            file_info_number[file_info_count]['后门程序'] = int(d['后门程序'])
            file_info[file_info_count]['后门程序'] = int(d['后门程序']) / all_file_number
        if int(d['勒索病毒']) != 0:
            file_info_number[file_info_count]['勒索病毒'] = int(d['勒索病毒'])
            file_info[file_info_count]['勒索病毒'] = int(d['勒索病毒']) / all_file_number
        if int(d['漏洞利用程序']) != 0:
            file_info_number[file_info_count]['漏洞利用程序'] = int(d['漏洞利用程序'])
            file_info[file_info_count]['漏洞利用程序'] = int(d['漏洞利用程序']) / all_file_number
        if int(d['木马程序']) != 0:
            file_info_number[file_info_count]['木马程序'] = int(d['木马程序'])
            file_info[file_info_count]['木马程序'] = int(d['木马程序']) / all_file_number
        if int(d['蠕虫病毒']) != 0:
            file_info_number[file_info_count]['蠕虫病毒'] = int(d['蠕虫病毒'])
            file_info[file_info_count]['蠕虫病毒'] = int(d['蠕虫病毒']) / all_file_number
        if int(d['挖矿程序']) != 0:
            file_info_number[file_info_count]['挖矿程序'] = int(d['挖矿程序'])
            file_info[file_info_count]['挖矿程序'] = int(d['挖矿程序']) / all_file_number
        if int(d['自变异木马']) != 0:
            file_info_number[file_info_count]['自变异木马'] = int(d['自变异木马'])
            file_info[file_info_count]['自变异木马'] = int(d['自变异木马']) / all_file_number
        file_info_count += 1
    # print(file_info)

    # 再修改一些文件信息的格式
    fileInfo = []
    for i in range(len(file_info)):
        fileInfo.append([])
        for f_key in file_info[i]:
            fileInfo[i].append(
                {
                    'filename': f_key,
                    'percent': file_info[i][f_key],
                    'fileNum': file_info_number[i][f_key]
                }
            )

    # data_color = pd.read_csv(str(BASE_DIR) + '//backend//malware_cluster.csv', usecols=[1, 21])

    # 聚类结果
    df = pd.read_csv(str(BASE_DIR) + '//backend//data//malware_cluster.csv', usecols=[1, 21])
    data_color = df.iloc[:, 0:2].values
    data_color_dict = {}
    for i in range(len(data_color)):
        data_color_dict[data_color[i][0]] = data_color[i][1]

    # 从小到大嵌套
    AS_ECS_TYPE = []
    for i in range(len(data)):
        AS_ECS_TYPE.append({
            'ECS_ID': data[i]['ESC_ID'],
            'type': levelValueInfo[i],
            'radius': radius[i],
            'fileInfo': fileInfo[i],
            'levelValue': levelValue[i],
            'isHighLight': isHighLight[i],
            'color': data_color_dict[data[i]['ESC_ID']]
        })

    AS_ECS = []
    AS_ECS_set = set()
    for i in range(len(AS_ECS_TYPE)):
        # 判断是否含有AS
        if data[i]['AS_ID'] not in AS_ECS_set:
            AS_ECS.append({
                'ECS_NUM': 1,
                'Region_ID': data[i]['Region_ID'],
                'VPC_ID': data[i]['VPC_ID'],
                'AS_ID': data[i]['AS_ID'],
                'AS_ECS_TYPE': [AS_ECS_TYPE[i]]
            })
            AS_ECS_set.add(data[i]['AS_ID'])
        else:
            for AS in AS_ECS:
                if AS['AS_ID'] == data[i]['AS_ID']:
                    AS['AS_ECS_TYPE'].append(AS_ECS_TYPE[i])
                    AS['ECS_NUM'] += 1

    Region_VPC = []
    Region_VPC_set = set()

    for i in range(len(AS_ECS)):
        # 判断是否含有vpc
        if AS_ECS[i]['VPC_ID'] not in Region_VPC_set:
            Region_VPC.append({
                'AS_NUM': 1,
                'ECS_NUM': AS_ECS[i]['ECS_NUM'],
                'VPC_ID': AS_ECS[i]['VPC_ID'],
                'AS_ECS': [AS_ECS[i]]
            })
            Region_VPC_set.add(AS_ECS[i]['VPC_ID'])
        else:
            for VPC in Region_VPC:
                if VPC['VPC_ID'] == AS_ECS[i]['VPC_ID']:
                    VPC['AS_ECS'].append(AS_ECS[i])
                    VPC['AS_NUM'] += 1
                    VPC['ECS_NUM'] += AS_ECS[i]['ECS_NUM']
    allData = []
    Region_set = set()
    for i in range(len(Region_VPC)):
        # 判断是否含有vpc
        if Region_VPC[i]['AS_ECS'][0]['Region_ID'] not in Region_set:
            allData.append({
                'VPC_NUM': 1,
                'AS_NUM': Region_VPC[i]['AS_NUM'],
                'ECS_NUM': Region_VPC[i]['ECS_NUM'],
                'Region_ID': Region_VPC[i]['AS_ECS'][0]['Region_ID'],
                'Region_VPC': [Region_VPC[i]]
            })
            Region_set.add(Region_VPC[i]['AS_ECS'][0]['Region_ID'])
        else:
            for Region in allData:
                if Region['Region_ID'] == Region_VPC[i]['AS_ECS'][0]['Region_ID']:
                    Region['Region_VPC'].append(Region_VPC[i])
                    Region['VPC_NUM'] += 1
                    Region['AS_NUM'] += Region_VPC[i]['AS_NUM']
                    Region['ECS_NUM'] += Region_VPC[i]['ECS_NUM']

    Data = {
        'allData': allData
    }
    return HttpResponse(json.dumps(Data), content_type='application/json')


def get_ECS_group_by_time(request):
    # 建议加一个过滤按钮
    # 获取malware_type_list、malware_subtype_list参数

    params = json.loads(request.body)
    malware_type_list = params['malwareType']
    malware_subtype_list = params['malwareSubtype']
    begintime_str = params['beginTime']
    endTime_str = params['endTime']
    begin_date = datetime.datetime.strptime(begintime_str, '%Y-%m-%d %H:%M:%S')
    end_date = datetime.datetime.strptime(endTime_str, '%Y-%m-%d %H:%M:%S')
    begin_timestamp = int(time.mktime(begin_date.timetuple()))
    end_timestamp = int(time.mktime(end_date.timetuple()))

    # # 时间
    # begintime_str = "2020-11-01 00:00:00"
    # endTime_str = "2020-11-02 00:00:00"
    # begin_date = datetime.datetime.strptime(begintime_str, '%Y-%m-%d %H:%M:%S')
    # end_date = datetime.datetime.strptime(endTime_str, '%Y-%m-%d %H:%M:%S')
    # begin_timestamp = int(time.mktime(begin_date.timetuple()))
    # end_timestamp = int(time.mktime(end_date.timetuple()))
    # # # # 文件过滤
    # malware_type_list = ['网站后门', '恶意进程', '恶意脚本']  #
    # malware_subtype_list = ['WEBSHELL', '恶意脚本文件']
    # malware_type_list = tuple(malware_type_list)

    # # 不定参数，生成where语句
    # where_type_str = ''
    # if malware_type_list != [] and malware_subtype_list != []:
    #     where_type_str = 'AND '
    #     is_first = True  # 是否为开头
    #     for i in malware_type_list:
    #         if is_first:
    #             where_type_str = where_type_str + '(malware_class = \"' + str(i) + '\" '
    #             is_first = False
    #         else:
    #             where_type_str = where_type_str + 'OR malware_class = \"' + str(i) + '\" '
    #
    #
    #     for i in malware_subtype_list:
    #         if is_first:
    #             where_type_str = where_type_str + '(malware_type = \"' + str(i) + '\" '
    #             is_first = False
    #         else:
    #             where_type_str = where_type_str + 'OR malware_type = \"' + str(i) + '\" '
    #     where_type_str += ') '

    # 这里按ESC_ID聚合
    cursor = connection.cursor()
    cursor.execute("select uuid AS ESC_ID, AS_ID, VPC_ID, Region_ID, "
                   "count(malware_type) AS malwareNumber,"
                   "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue,"
                   "sum(case when malware_type='WEBSHELL'then 1 else 0 end) as webshell, "
                   "sum(case when malware_type='DDOS木马' then 1 else 0 end) as DDOS木马,"
                   "sum(case when malware_type='被污染的基础软件' then 1 else 0 end) as 被污染的基础软件,"
                   "sum(case when malware_type='恶意程序' then 1 else 0 end) as 恶意程序,"
                   "sum(case when malware_type='恶意脚本文件' then 1 else 0 end) as 恶意脚本文件,"
                   "sum(case when malware_type='感染型病毒' then 1 else 0 end) as 感染型病毒,"
                   "sum(case when malware_type='黑客工具' then 1 else 0 end) as 黑客工具,"
                   "sum(case when malware_type='后门程序' then 1 else 0 end) as 后门程序,"
                   "sum(case when malware_type='勒索病毒' then 1 else 0 end) as 勒索病毒,"
                   "sum(case when malware_type='漏洞利用程序' then 1 else 0 end) as 漏洞利用程序,"
                   "sum(case when malware_type='木马程序' then 1 else 0 end) as 木马程序,"
                   "sum(case when malware_type='蠕虫病毒' then 1 else 0 end) as 蠕虫病毒,"
                   "sum(case when malware_type='挖矿程序' then 1 else 0 end) as 挖矿程序,"
                   "sum(case when malware_type='自变异木马' then 1 else 0 end) as 自变异木马 "
                   "from malware_base_info AS a LEFT JOIN user_netstate_info AS b ON a.uuid=b.ECS_ID  where UNIX_TIMESTAMP(first_time) > '{0}' AND UNIX_TIMESTAMP(first_time) < '{1}' group by uuid".format(
        begin_timestamp, end_timestamp))

    desc = cursor.description
    alldata = cursor.fetchall()
    data = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    if data == []:
        Data = {}
        return HttpResponse(json.dumps(Data), content_type='application/json')

    # 强塞Region vpc as数据
    # for d in data:

    # print(data)
    # 态势值对应的 danger | warn | safe
    # 先求得态势值10% 60%的值
    levelValue = []  # 保存态势值的数值
    for d in data:
        levelValue.append(int(d['levelValue']))
    levelValueSort = levelValue
    levelValueSort = sorted(levelValueSort)

    point90 = levelValueSort[math.floor(len(levelValueSort) / 10 * 9)]
    point40 = levelValueSort[math.floor(len(levelValueSort) / 10 * 4)]
    levelValueInfo = []  # 保存态势值的颜色
    for l in levelValue:
        if l < point40:
            levelValueInfo.append('safe')
        elif l >= point40 and l < point90:
            levelValueInfo.append('warn')
        else:
            levelValueInfo.append('danger')
    # print(levelValueInfo)

    # 处理一下阈值 9 和 64  小于9不显示圆形 大于64显示file_info
    radius = []
    for d in data:
        malwareNumber = d['malwareNumber']
        if malwareNumber < 9:
            radius.append(0)
        elif malwareNumber >= 9 and malwareNumber <= 64:
            radius.append((math.sqrt(malwareNumber) - 3) / 5 * 10)
        else:
            radius.append(-1)

    # webshell, DDOS木马,被污染的基础软件,恶意程序,恶意脚本文件,感染型病毒,黑客工具,后门程序,勒索病毒,漏洞利用程序,木马程序,蠕虫病毒,挖矿程序,自变异木马

    # 处理文件信息
    file_info_count = 0
    file_info = []
    for d in data:
        file_info.append({})
        all_file_number = d['malwareNumber']
        if int(d['webshell']) != 0:
            file_info[file_info_count]['webshell'] = int(d['webshell']) / all_file_number
        if int(d['DDOS木马']) != 0:
            file_info[file_info_count]['DDOS木马'] = int(d['DDOS木马']) / all_file_number
        if int(d['被污染的基础软件']) != 0:
            file_info[file_info_count]['被污染的基础软件'] = int(d['被污染的基础软件']) / all_file_number
        if int(d['恶意程序']) != 0:
            file_info[file_info_count]['恶意程序'] = int(d['恶意程序']) / all_file_number
        if int(d['恶意脚本文件']) != 0:
            file_info[file_info_count]['恶意脚本文件'] = int(d['恶意脚本文件']) / all_file_number
        if int(d['感染型病毒']) != 0:
            file_info[file_info_count]['感染型病毒'] = int(d['感染型病毒']) / all_file_number
        if int(d['黑客工具']) != 0:
            file_info[file_info_count]['黑客工具'] = int(d['黑客工具']) / all_file_number
        if int(d['后门程序']) != 0:
            file_info[file_info_count]['后门程序'] = int(d['后门程序']) / all_file_number
        if int(d['勒索病毒']) != 0:
            file_info[file_info_count]['勒索病毒'] = int(d['勒索病毒']) / all_file_number
        if int(d['漏洞利用程序']) != 0:
            file_info[file_info_count]['漏洞利用程序'] = int(d['漏洞利用程序']) / all_file_number
        if int(d['木马程序']) != 0:
            file_info[file_info_count]['木马程序'] = int(d['木马程序']) / all_file_number
        if int(d['蠕虫病毒']) != 0:
            file_info[file_info_count]['蠕虫病毒'] = int(d['蠕虫病毒']) / all_file_number
        if int(d['挖矿程序']) != 0:
            file_info[file_info_count]['挖矿程序'] = int(d['挖矿程序']) / all_file_number
        if int(d['自变异木马']) != 0:
            file_info[file_info_count]['自变异木马'] = int(d['自变异木马']) / all_file_number
        file_info_count += 1
    # print(file_info)

    # 再修改一些文件信息的格式
    fileInfo = []
    for i in range(len(file_info)):
        fileInfo.append([])
        for f_key in file_info[i]:
            fileInfo[i].append(
                {
                    'filename': f_key,
                    'percent': file_info[i][f_key]
                }
            )

    # print('fileInfo', fileInfo)

    # 从小到大嵌套
    AS_ECS_TYPE = []
    for i in range(len(data)):
        AS_ECS_TYPE.append({
            'ECS_ID': data[i]['ESC_ID'],
            'type': levelValueInfo[i],
            'radius': radius[i],
            'fileInfo': fileInfo[i],
        })

    AS_ECS = []
    AS_ECS_set = set()
    for i in range(len(AS_ECS_TYPE)):
        # 判断是否含有AS
        if data[i]['AS_ID'] not in AS_ECS_set:
            AS_ECS.append({
                'Region_ID': data[i]['Region_ID'],
                'VPC_ID': data[i]['VPC_ID'],
                'AS_ID': data[i]['AS_ID'],
                'AS_ECS_TYPE': [AS_ECS_TYPE[i]]
            })
            AS_ECS_set.add(data[i]['AS_ID'])
        else:
            for AS in AS_ECS:
                if AS['AS_ID'] == data[i]['AS_ID']:
                    AS['AS_ECS_TYPE'].append(AS_ECS_TYPE[i])

    Region_VPC = []
    Region_VPC_set = set()

    for i in range(len(AS_ECS)):
        # 判断是否含有vpc
        if AS_ECS[i]['VPC_ID'] not in Region_VPC_set:
            Region_VPC.append({
                'VPC_ID': AS_ECS[i]['VPC_ID'],
                'AS_ECS': [AS_ECS[i]]
            })
            Region_VPC_set.add(AS_ECS[i]['VPC_ID'])
        else:
            for VPC in Region_VPC:
                if VPC['VPC_ID'] == AS_ECS[i]['VPC_ID']:
                    VPC['AS_ECS'].append(AS_ECS[i])

    allData = []
    Region_set = set()
    for i in range(len(Region_VPC)):
        # 判断是否含有vpc
        if Region_VPC[i]['AS_ECS'][0]['Region_ID'] not in Region_set:
            allData.append({
                'Region_ID': Region_VPC[i]['AS_ECS'][0]['Region_ID'],
                'Region_VPC': [Region_VPC[i]]
            })
            Region_set.add(Region_VPC[i]['AS_ECS'][0]['Region_ID'])
        else:
            for Region in allData:
                if Region['Region_ID'] == Region_VPC[i]['AS_ECS'][0]['Region_ID']:
                    Region['Region_VPC'].append(Region_VPC[i])

    # begintime_str = "2010-11-01 06:00:00"
    # endTime_str = "2020-11-02 00:00:00"

    # 获取恶意文件数量(先按出现次数来计算)
    cursor.execute("select count(*) AS malwareNumber,"
                   "SUM(CASE malware_type WHEN 'WEBSHELL' Then 1 ELSE 0 END) AS webshellNumber, "
                   "SUM(CASE malware_type WHEN '被污染的基础软件' Then 1 ELSE 0 END) AS biNumber, "
                   "SUM(CASE malware_type WHEN '恶意脚本文件' Then 1 ELSE 0 END) AS scriptNumber,"
                   "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue "
                   "from malware_base_info where UNIX_TIMESTAMP(first_time) > '{0}' and UNIX_TIMESTAMP(first_time) < '{1}'".format(
        begin_timestamp, end_timestamp))

    desc = cursor.description
    alldata = cursor.fetchall()
    fileNumber = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    # print(fileNumber)
    # print('fileNumber', len(fileNumber))

    Data = {
        'timeStamp': begintime_str,
        'levelValue': int(fileNumber[0]['levelValue']),
        'files': {
            'malwareNumber': int(fileNumber[0]['malwareNumber']),
            'webshellNumber': int(str(fileNumber[0]['webshellNumber'])),
            'biNumber': int(str(fileNumber[0]['biNumber'])),
            'scriptNumber': int(str(fileNumber[0]['scriptNumber'])),
        },
        'ECSLevelValue': allData
    }

    # print(Data)
    # # return HttpResponse("ok")

    return HttpResponse(json.dumps(Data), content_type='application/json')


# 界面二 三个ecs
# def get_bad_file_by_ECS(request):
#     # region_ID = params['Region_ID']
#
#     ECS_ID = ['231f6e52cc327c5b9f7407ab6a4672fc', 'e4badaeb269c4eb3c4c2ed62ba095cdc',
#               '97c61da87411b82b8c9ef67ee3c82ac6']
#     cursor = connection.cursor()
#     cursor.execute("select uuid AS ESC_ID, VPC_ID, AS_ID, Region_ID, "
#                    "count(*) AS malwareNumber,"
#                    "sum(case when malware_class='网站后门'then 1 else 0 end) as 网站后门, "
#                    "sum(case when malware_class='恶意进程'then 1 else 0 end) as 恶意进程, "
#                    "sum(case when malware_class='恶意脚本'then 1 else 0 end) as 恶意脚本, "
#                    "sum(case when malware_type='WEBSHELL'then 1 else 0 end) as webshell, "
#                    "sum(case when malware_type='DDOS木马' then 1 else 0 end) as DDOS木马,"
#                    "sum(case when malware_type='被污染的基础软件' then 1 else 0 end) as 被污染的基础软件,"
#                    "sum(case when malware_type='恶意程序' then 1 else 0 end) as 恶意程序,"
#                    "sum(case when malware_type='恶意脚本文件' then 1 else 0 end) as 恶意脚本文件,"
#                    "sum(case when malware_type='感染型病毒' then 1 else 0 end) as 感染型病毒,"
#                    "sum(case when malware_type='黑客工具' then 1 else 0 end) as 黑客工具,"
#                    "sum(case when malware_type='后门程序' then 1 else 0 end) as 后门程序,"
#                    "sum(case when malware_type='勒索病毒' then 1 else 0 end) as 勒索病毒,"
#                    "sum(case when malware_type='漏洞利用程序' then 1 else 0 end) as 漏洞利用程序,"
#                    "sum(case when malware_type='木马程序' then 1 else 0 end) as 木马程序,"
#                    "sum(case when malware_type='蠕虫病毒' then 1 else 0 end) as 蠕虫病毒,"
#                    "sum(case when malware_type='挖矿程序' then 1 else 0 end) as 挖矿程序,"
#                    "sum(case when malware_type='自变异木马' then 1 else 0 end) as 自变异木马, "
#                    "sum(case when file_type='WEBSHELL' then 1 else 0 end) as WEBSHELL, "
#                    "sum(case when file_type='BIN' then 1 else 0 end) as BIN, "
#                    "sum(case when file_type='SCRIPT' then 1 else 0 end) as SCRIPT "
#                    "from malware_base_info AS a LEFT JOIN user_netstate_info AS b ON a.uuid=b.ECS_ID where uuid = '{0}' or uuid = '{1}' or uuid = '{2}'group by uuid".format(ECS_ID[0], ECS_ID[1], ECS_ID[2]))
#
#     desc = cursor.description
#     alldata = cursor.fetchall()
#     data = [dict(zip([col[0] for col in desc], row)) for row in alldata]
#
#     # 处理文件信息
#     file_info_count = 0
#     Data = []
#
#     for d in data:
#         Data.append({
#             'ESC_ID': d['ESC_ID'],
#             'VPC_ID': d['VPC_ID'],
#             'AS_ID': d['AS_ID'],
#             'Region': d['Region_ID']
#         })
#
#         malware_type = []
#         malware_subtype = []
#         file_type = []
#         all_file_number = d['malwareNumber']
#
#         if int(d['webshell']) != 0:
#             malware_type.append({
#                 'malwareTypeName': 'webshell',
#                 'percent': int(d['webshell']) / all_file_number
#             })
#         if int(d['DDOS木马']) != 0:
#             malware_type.append({
#                 'malwareTypeName': 'DDOS木马',
#                 'percent': int(d['DDOS木马']) / all_file_number
#             })
#         if int(d['被污染的基础软件']) != 0:
#             malware_type.append({
#                 'malwareTypeName': 'webshell',
#                 'percent': int(d['webshell']) / all_file_number
#             })
#         if int(d['恶意程序']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '恶意程序',
#                 'percent': int(d['恶意程序']) / all_file_number
#             })
#         if int(d['恶意脚本文件']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '恶意脚本文件',
#                 'percent': int(d['恶意脚本文件']) / all_file_number
#             })
#         if int(d['感染型病毒']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '感染型病毒',
#                 'percent': int(d['感染型病毒']) / all_file_number
#             })
#         if int(d['黑客工具']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '黑客工具',
#                 'percent': int(d['黑客工具']) / all_file_number
#             })
#         if int(d['后门程序']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '后门程序',
#                 'percent': int(d['后门程序']) / all_file_number
#             })
#         if int(d['勒索病毒']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '勒索病毒',
#                 'percent': int(d['勒索病毒']) / all_file_number
#             })
#         if int(d['漏洞利用程序']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '漏洞利用程序',
#                 'percent': int(d['漏洞利用程序']) / all_file_number
#             })
#         if int(d['木马程序']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '木马程序',
#                 'percent': int(d['木马程序']) / all_file_number
#             })
#         if int(d['蠕虫病毒']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '蠕虫病毒',
#                 'percent': int(d['蠕虫病毒']) / all_file_number
#             })
#         if int(d['挖矿程序']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '挖矿程序',
#                 'percent': int(d['挖矿程序']) / all_file_number
#             })
#         if int(d['自变异木马']) != 0:
#             malware_type.append({
#                 'malwareTypeName': '自变异木马',
#                 'percent': int(d['自变异木马']) / all_file_number
#             })
#
#         if int(d['网站后门']) != 0:
#             malware_subtype.append({
#                 'malwareTypeName': '网站后门',
#                 'percent': int(d['网站后门']) / all_file_number
#             })
#
#         if int(d['恶意进程']) != 0:
#             malware_subtype.append({
#                 'malwareTypeName': '恶意进程',
#                 'percent': int(d['恶意进程']) / all_file_number
#             })
#
#         if int(d['恶意脚本']) != 0:
#             malware_subtype.append({
#                 'malwareTypeName': '恶意脚本',
#                 'percent': int(d['恶意脚本']) / all_file_number
#             })
#
#         if int(d['WEBSHELL']) != 0:
#             file_type.append({
#                 'fileTypeName': 'WEBSHELL',
#                 'percent': int(d['WEBSHELL']) / all_file_number
#             })
#
#         if int(d['BIN']) != 0:
#             file_type.append({
#                 'fileTypeName': 'BIN',
#                 'percent': int(d['BIN']) / all_file_number
#             })
#
#         if int(d['SCRIPT']) != 0:
#             file_type.append({
#                 'fileTypeName': 'SCRIPT',
#                 'percent': int(d['SCRIPT']) / all_file_number
#             })
#
#         Data[file_info_count]['malware_subtype'] = malware_type
#         Data[file_info_count]['malware_type'] = malware_subtype
#         Data[file_info_count]['file_type'] = file_type
#         file_info_count += 1
#
#     print(Data)
#
#     datas = Data
#     jsonData = json.dumps(datas)
#     fileObject = open('data_3ecs_include_file_type_v2.json', 'w')
#     fileObject.write(jsonData)
#     fileObject.close()
#
#     return HttpResponse("ok")