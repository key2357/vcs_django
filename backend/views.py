from django.http import HttpResponse
from django.db import connection
from backend.util import get_file_where_str, get_file_and_time_where_str, get_time_str, get_time_where_str
from vcs_django.settings import BASE_DIR
from backend.config import MALWARE_SUBTYPE, FINAL_TIME, INIT_TIME
import pandas as pd
import numpy as np
import time
import datetime
import random
import json
import math
import networkx as nx


# import matplotlib.pyplot as plt


def test(request):
    cursor = connection.cursor()
    cursor.execute("select uuid from malware_base_info "
                   "where first_time > '2017-11-29 00:00:00' and first_time < '2020-11-03 00:00:00' group by uuid")

    desc = cursor.description
    all_data = cursor.fetchall()
    engines_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    # uuid_set = set()
    # for en in engines_data:
    #     uuid_set.add(en['uuid'])  # 3797  3797
    print(len(engines_data))

    #
    # print(len(uuid_set))
    # begin_time_number = 0
    # end_time_number = 1
    # begin_time_stamp = begin_time_number * (FINAL_TIME - INIT_TIME) + INIT_TIME
    # end_time_number = end_time_number * (FINAL_TIME - INIT_TIME) + INIT_TIME
    # begin_time_array = datetime.datetime.fromtimestamp(begin_time_stamp)
    # end_time_array = datetime.datetime.fromtimestamp(end_time_number)
    # begin_time_str = str(begin_time_array.strftime("%Y-%m-%d %H:%M:%S"))
    #
    # end_time_str = str(end_time_array.strftime("%Y-%m-%d %H:%M:%S"))
    # print(begin_time_str , end_time_str)

    # begintime_str = '2017-11-29 00:00:00'
    # endTime_str = '2020-11-03 00:00:00'
    # begin_date = datetime.datetime.strptime(begintime_str, '%Y-%m-%d %H:%M:%S')
    # end_date = datetime.datetime.strptime(endTime_str, '%Y-%m-%d %H:%M:%S')
    # begin_timestamp = int(time.mktime(begin_date.timetuple()))
    # end_timestamp = int(time.mktime(end_date.timetuple()))
    # print(begin_timestamp, end_timestamp)

    Data = {}
    return HttpResponse(json.dumps(Data), content_type='application/json')


# 这个可以改为静态的了
def get_base_info(request):
    cursor = connection.cursor()
    # 查询资产数量
    cursor.execute("select count(DISTINCT ECS_ID) AS ecsNumber, "
                   "count(DISTINCT AS_ID) AS asNumber, "
                   "count(DISTINCT VPC_ID) AS vpcNumber, "
                   "count(DISTINCT Region_ID) AS regionNumber from user_netstate_info")

    desc = cursor.description
    all_data = cursor.fetchall()
    engines_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    # 查询文件数量
    cursor.execute("select count(*) AS malwareNumber, "
                   "SUM(CASE file_type WHEN 'WEBSHELL' Then 1 ELSE 0 END) AS webshellNumber, "
                   "SUM(CASE file_type WHEN 'BIN' Then 1 ELSE 0 END) AS biNumber, "
                   "SUM(CASE file_type WHEN 'SCRIPT' Then 1 ELSE 0 END) AS scriptNumber from "
                   "(select file_type from malware_base_info group by malware_md5) t")

    desc = cursor.description
    all_data = cursor.fetchall()
    file_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    cursor.close()
    connection.close()

    # 处理为借口格式的数据
    Data = {
        'username': 'Admin',
        'engines': {
            'regionNumber': engines_data[0]['regionNumber'],
            'vpcNumber': engines_data[0]['vpcNumber'],
            'asNumber': engines_data[0]['asNumber'],
            'ecsNumber': engines_data[0]['ecsNumber'],
        },
        'files': {
            'malwareNumber': file_data[0]['malwareNumber'],
            'webshellNumber': int(str(file_data[0]['webshellNumber'])),
            'biNumber': int(str(file_data[0]['biNumber'])),
            'scriptNumber': int(str(file_data[0]['scriptNumber'])),
        }
    }

    return HttpResponse(json.dumps(Data), content_type='application/json')


def get_force(request):
    # 文件过滤
    params = json.loads(request.body)
    file_filter = params['filter']

    # 文件过滤为空的逻辑，以确定where_str
    # file_filter = {
    #     'malwareType': ['网站后门', '恶意进程'],
    #     'malwareSubtype': ['WEBSHELL', '挖矿程序'],
    #     'fileType': ['BIN', 'WEBSHELL']
    # }

    if file_filter:
        malware_type_list = file_filter['malwareType']
        malware_subtype_list = file_filter['malwareSubtype']
        malware_filetype_list = file_filter['fileType']
        # where_str = get_file_where_str(malware_type_list, malware_subtype_list, malware_filetype_list)
        begin_time_number = 0
        end_time_number = 1
        begin_time_str, end_time_str = get_time_str(begin_time_number, end_time_number)
        where_str = get_file_and_time_where_str(malware_type_list, malware_subtype_list, malware_filetype_list,
                                                begin_time_str, end_time_str)
    else:
        where_str = ''

    cursor = connection.cursor()
    # 获取总态势值 耗时2.5s左右
    cursor.execute("select concat(DATE_FORMAT(first_time, '%Y-%m-%d '),'00:00:00') as time,"
                   "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue "
                   "from malware_base_info " + where_str + " group by DATE_FORMAT(first_time, '%Y-%m-%d')")

    desc = cursor.description
    all_data = cursor.fetchall()
    force_value = [dict(zip([col[0] for col in desc], row)) for row in all_data]
    force_value = sorted(force_value, key=lambda value: value['time'])

    # 处理为接口格式
    ReturnData = []
    for i in force_value:
        if i['time'] != '0000-00-00 00:00:00':
            ReturnData.append({
                'timestamp': i['time'],
                'force_value': math.sqrt(int(i['levelValue']))
            })

    return HttpResponse(json.dumps(ReturnData), content_type='application/json')


# view3 态势等级视图 获取每个ECS的信息（包括ECS_ID、态势等级、聚类结果、半径、态势值、是否高危、是否高亮、文件信息）
def get_ecs_force(request):
    params = json.loads(request.body)
    slice = params['slice']
    file_filter = params['fileFilter']
    file = params['file']

    # slice = {
    #     'beginTime': 0.2,
    #     'endTime': 0.21
    # }
    #
    # file_filter = {
    #     'malwareType': ['网站后门', '恶意进程'],
    #     'malwareSubtype': ['WEBSHELL', '挖矿程序'],
    #     'fileType': ['BIN', 'WEBSHELL']
    # }
    #
    # file = {
    #     'categories': 'malwareType',
    #     'subtype': '被污染的基础软件'
    # }

    # 时间片或文件过滤为空的逻辑，以确定where_str
    if file_filter and slice:
        begin_time_number = slice['beginTime']
        end_time_number = slice['endTime']
        begin_time_str, end_time_str = get_time_str(begin_time_number, end_time_number)
        malware_type_list = file_filter['malwareType']
        malware_subtype_list = file_filter['malwareSubtype']
        malware_filetype_list = file_filter['fileType']
        where_str = get_file_and_time_where_str(malware_type_list, malware_subtype_list, malware_filetype_list,
                                                begin_time_str, end_time_str)
    elif file_filter:  # 加个时间会不会比较好
        malware_type_list = file_filter['malwareType']
        malware_subtype_list = file_filter['malwareSubtype']
        malware_filetype_list = file_filter['fileType']
        # where_str = get_file_where_str(malware_type_list, malware_subtype_list, malware_filetype_list)
        begin_time_number = 0
        end_time_number = 1
        begin_time_str, end_time_str = get_time_str(begin_time_number, end_time_number)
        where_str = get_file_and_time_where_str(malware_type_list, malware_subtype_list, malware_filetype_list,
                                                begin_time_str, end_time_str)
    elif slice:
        begin_time_number = slice['beginTime']
        end_time_number = slice['endTime']
        begin_time_str, end_time_str = get_time_str(begin_time_number, end_time_number)
        where_str = get_time_where_str(begin_time_str, end_time_str)
        begin_time_number = 0
    else:
        begin_time_number = 0
        where_str = ''
    cursor = connection.cursor()
    cursor.execute(
        "select uuid AS ESC_ID, AS_ID, VPC_ID, Region_ID, "
        "malware_class as malwareType, malware_type as malwareSubtype, file_type as FileType, "
        "count(malware_type) AS malwareNumber, "
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
    all_data = cursor.fetchall()
    ecs_force_and_file = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    print(len(ecs_force_and_file))
    if not ecs_force_and_file:
        ReturnData = {}
        return HttpResponse(json.dumps(ReturnData), content_type='application/json')

    # 态势值对应的 danger | warn | safe | none
    # 先求得态势值10% 60%的值
    level_value = []  # 保存态势值的数值
    total_value = 0
    for d in ecs_force_and_file:
        level_value.append(int(d['levelValue']))
        total_value += int(d['levelValue'])
    level_value_sort = level_value
    level_value_sort = sorted(level_value_sort)
    point90 = level_value_sort[math.floor(len(level_value_sort) / 10 * 9)]
    point40 = level_value_sort[math.floor(len(level_value_sort) / 10 * 4)]
    point97 = level_value_sort[math.floor(len(level_value_sort) / 10 * 9.7)]
    level_value_info = []  # 保存态势值的颜色
    is_extremely_dangerous = []  # 保存ecs是否高危
    for le in level_value:
        if le == 0:
            level_value_info.append('none')
        elif le < point40:
            level_value_info.append('safe')
        elif point40 <= le < point90:
            level_value_info.append('warn')
        else:
            level_value_info.append('danger')
        if le > point97:
            is_extremely_dangerous.append(True)
        else:
            is_extremely_dangerous.append(False)

    # 处理一下阈值 9 和 64  小于9不显示圆形 大于64显示file_info
    radius = []
    for d in ecs_force_and_file:
        malware_number = d['malwareNumber']
        if malware_number < 9:
            radius.append(0)
        elif 9 <= malware_number <= 64:
            radius.append((math.sqrt(malware_number) - 3) / 5 * 10)
        else:
            radius.append(-1)

    # webshell, DDOS木马,被污染的基础软件,恶意程序,恶意脚本文件,感染型病毒,黑客工具,后门程序,勒索病毒,漏洞利用程序,木马程序,蠕虫病毒,挖矿程序,自变异木马
    # 处理文件信息
    file_info_count = 0
    file_info = []
    file_info_number = []
    for d in ecs_force_and_file:
        file_info.append({})
        file_info_number.append({})
        all_file_number = d['malwareNumber']
        for sub_type in MALWARE_SUBTYPE:
            if int(d[sub_type]) != 0:
                file_info_number[file_info_count][sub_type] = int(d[sub_type])
                file_info[file_info_count][sub_type] = int(d[sub_type]) / all_file_number
        file_info_count += 1

    # 再修改一些文件信息的格式
    file_info_result = []

    for i in range(len(file_info)):
        file_info_result.append([])
        for f_key in file_info[i]:
            file_info_result[i].append(
                {
                    'filename': f_key,
                    'percent': file_info[i][f_key],
                    'fileNum': file_info_number[i][f_key]
                }
            )

    # 计算是否高亮
    is_highlight = []
    if file:
        categories = file['categories']
        subtype = file['subtype']
        for d in ecs_force_and_file:
            if d[categories] == subtype:
                is_highlight.append(True)
            else:
                is_highlight.append(False)
    else:
        for i in range(len(ecs_force_and_file)):
            is_highlight.append(False)

    # 从小到大嵌套
    AS_ECS_TYPE = []
    for i in range(len(ecs_force_and_file)):
        AS_ECS_TYPE.append({
            'ECS_ID': ecs_force_and_file[i]['ESC_ID'],
            'type': level_value_info[i],
            'radius': radius[i],
            'fileInfo': file_info_result[i],
            'forceValue': math.sqrt(level_value[i]),
            'isExtremelyDangerous': is_extremely_dangerous[i],
            'isHighLight': is_highlight[i],
        })

    AS_ECS = []
    AS_ECS_set = set()
    for i in range(len(AS_ECS_TYPE)):
        # 判断是否含有AS
        if ecs_force_and_file[i]['AS_ID'] not in AS_ECS_set:
            AS_ECS.append({
                'ECS_NUM': 1,
                'Region_ID': ecs_force_and_file[i]['Region_ID'],
                'VPC_ID': ecs_force_and_file[i]['VPC_ID'],
                'AS_ID': ecs_force_and_file[i]['AS_ID'],
                'AS_ECS_TYPE': [AS_ECS_TYPE[i]]
            })
            AS_ECS_set.add(ecs_force_and_file[i]['AS_ID'])
        else:
            for AS in AS_ECS:
                if AS['AS_ID'] == ecs_force_and_file[i]['AS_ID']:
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

    # 查询文件数量
    cursor.execute("select count(*) AS malwareNumber, "
                   "SUM(CASE file_type WHEN 'WEBSHELL' Then 1 ELSE 0 END) AS webshellNumber, "
                   "SUM(CASE file_type WHEN 'BIN' Then 1 ELSE 0 END) AS biNumber, "
                   "SUM(CASE file_type WHEN 'SCRIPT' Then 1 ELSE 0 END) AS scriptNumber from "
                   "(select file_type from malware_base_info " + where_str + "group by malware_md5) t")

    desc = cursor.description
    all_data = cursor.fetchall()
    file_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]
    ReturnData = {
        'timeStamp': begin_time_number,
        'totalValue': total_value,
        'allData': allData,
        'files': {
            'malwareNumber': file_data[0]['malwareNumber'],
            'webshellNumber': int(str(file_data[0]['webshellNumber'])),
            'biNumber': int(str(file_data[0]['biNumber'])),
            'scriptNumber': int(str(file_data[0]['scriptNumber'])),
        }
    }
    return HttpResponse(json.dumps(ReturnData), content_type='application/json')


# 这个暂时没改
def get_force_graph_by_time(request):
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
                   "where UNIX_TIMESTAMP(first_time) > '{0}' AND UNIX_TIMESTAMP(first_time) < '{1}' group by malware_md5".format(
        begin_timestamp, end_timestamp))

    desc = cursor.description
    alldata = cursor.fetchall()
    data = [dict(zip([col[0] for col in desc], row)) for row in alldata]

    nodes = []
    for d in data:
        nodes.append({
            'id': d['malware_md5'],
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
