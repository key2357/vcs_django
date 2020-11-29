from django.http import HttpResponse
from django.db import connection
from backend.util import get_file_where_str, get_file_and_time_where_str, get_time_str, get_time_where_str, \
    get_slice_where_str, get_timestamp, has_filter_func
from vcs_django.settings import BASE_DIR
from backend.config import MALWARE_SUBTYPE, FINAL_TIME, INIT_TIME
import pandas as pd
import numpy as np
import time
import random
import json
import math
import networkx as nx


# import matplotlib.pyplot as plt
def test(request):
    # 处理全连接图为环形
    # error_node = [123, 143, 149, 166, 187, 250, 284]  # 包含全连接和非全连接的
    # error_node_all_connection = [105, 242]
    cursor = connection.cursor()
    cursor.execute("select `source`, target, similarity from similarity_info")
    desc = cursor.description
    all_data = cursor.fetchall()
    row_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]
    print(len(row_data))
    count = 0
    for r in row_data:
        if r['similarity'] == 1:
            count += 1
    print(count)

    # 再生成除环以外的边
    # for le in data['links']:
    #     # 判断两者不在一个集合内
    #     source = le['source']
    #     target = le['target']
    #
    #     is_in_set = False
    #     for s in set_list:
    #         if source in s and target in s:
    #             is_in_set = True
    #
    #     if not is_in_set:
    #         if (le['source'], le['target']) not in links_set:
    #             links_after_handle.append({
    #                 "source": le['source'],
    #                 "target": le['target'],
    #                 "value": le['value'],
    #                 "isLoop": False
    #             })

    # data['links'] = links_after_handle
    # c = 296
    # json_data = json.dumps(data)
    # file_object = open(str(BASE_DIR) + '//slice_' + str(c) + '.json', 'w')
    # file_object.write(json_data)
    # file_object.close()

    # 测试有多少空数据
    # df = pd.read_csv(str(BASE_DIR) + '//backend//data//file_md5.csv', usecols=[0])
    # file_md5 = df.iloc[:, 0:1].values
    # file_md5_info = []
    # for i in range(len(file_md5)):
    #     file_md5_info.append(file_md5[i][0])
    #
    # cursor = connection.cursor()
    # cursor.execute("select malware_md5, create_time from malware_base_info group by malware_md5")
    # desc = cursor.description
    # all_data = cursor.fetchall()
    # time_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]
    #
    # time_dict = {}
    # x = 0
    # for t in time_data:
    #     if t['create_time']:
    #         time_dict[t['malware_md5']] = t['create_time'].strftime('%Y-%m-%d %H:%M:%S')
    #     elif t['malware_md5'] in time_dict and time_dict[t['malware_md5']] != 0 and t['create_time'] == 0:
    #         x += 1
    #     else:
    #         time_dict[t['malware_md5']] = '0'
    #
    # file_time = []
    # for f in file_md5_info:
    #     if time_dict[f] != '0':
    #         file_time.append(time_dict[f])
    # print(len(file_time))
    # print(x)
    data = {}
    return HttpResponse(json.dumps(data), content_type='application/json')


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

    has_filter = has_filter_func(file_filter)

    if has_filter:
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
        begin_time_number = 0
        end_time_number = 1
        begin_time_str, end_time_str = get_time_str(begin_time_number, end_time_number)
        where_str = get_time_where_str(begin_time_str, end_time_str)
    cursor = connection.cursor()
    # 获取总态势值 耗时2.5s左右
    # cursor.execute("select concat(DATE_FORMAT(first_time, '%Y-%m-%d '),'00:00:00') as time,"
    #                "SUM(CASE level WHEN 'lower' Then 1 WHEN 'high' THEN 3 WHEN 'serious' THEN 4 ELSE 0 END) AS levelValue "
    #                "from malware_base_info " + where_str + " group by DATE_FORMAT(first_time, '%Y-%m-%d')")

    # 获取文件数量
    cursor.execute("select concat(DATE_FORMAT(create_time, '%Y-%m-%d '),'00:00:00') as time, "
                   "count(*) AS malwareNumber "
                   "from (select create_time, malware_class, malware_type, file_type from malware_base_info "
                   + where_str + " group by malware_md5) t group by DATE_FORMAT(create_time, '%Y-%m-%d')")
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
                'fileNum': int(i['malwareNumber'])
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

    has_filter = has_filter_func(file_filter)

    # 时间片或文件过滤为空的逻辑，以确定where_str
    if has_filter and slice:
        begin_time_number = slice['beginTime']
        end_time_number = slice['endTime']
        begin_time_str, end_time_str = get_time_str(begin_time_number, end_time_number)
        malware_type_list = file_filter['malwareType']
        malware_subtype_list = file_filter['malwareSubtype']
        malware_filetype_list = file_filter['fileType']
        where_str = get_file_and_time_where_str(malware_type_list, malware_subtype_list, malware_filetype_list,
                                                begin_time_str, end_time_str)
    elif has_filter:  # 加个时间会不会比较好
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
    else:
        begin_time_number = 0
        where_str = ''
    cursor = connection.cursor()

    cursor.execute(
        "select uuid AS ESC_ID, AS_ID, VPC_ID, Region_ID, "
        "malware_class as malwareType, malware_type as malwareSubtype, file_type as FileType, "
        "count(malware_type) AS malwareNumber, "
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
        "from (select uuid, malware_class, malware_type, file_type from malware_base_info " + where_str + " group by malware_md5) AS a "
        "LEFT JOIN user_netstate_info AS b ON a.uuid=b.ECS_ID group by uuid")

    desc = cursor.description
    all_data = cursor.fetchall()
    ecs_force_and_file = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    if not ecs_force_and_file:
        ReturnData = {}
        return HttpResponse(json.dumps(ReturnData), content_type='application/json')

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

    # 态势值对应的 danger | warn | safe | none 全改为文件数量
    # 先求得态势值10% 60%的值
    file_num = []  # 保存态势值的数值
    total_value = 0
    for d in ecs_force_and_file:
        file_num.append(int(d['malwareNumber']))
        total_value += int(d['malwareNumber'])
    level_value_sort = file_num
    level_value_sort = sorted(level_value_sort)
    point90 = level_value_sort[math.floor(len(level_value_sort) / 10 * 9)]
    point40 = level_value_sort[math.floor(len(level_value_sort) / 10 * 4)]
    point97 = level_value_sort[math.floor(len(level_value_sort) / 10 * 9.7)]
    level_value_info = []  # 保存态势值的颜色
    is_extremely_dangerous = []  # 保存ecs是否高危
    for le in file_num:
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
            # 'forceValue': math.sqrt(level_value[i]),
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


# 用真数据
def get_force_graph_by_time(request):
    params = json.loads(request.body)
    slice = params['slice']
    file_filter = params['fileFilter']

    # slice = {
    #     'beginTime': 0,
    #     'endTime': 1
    # }
    #
    # file_filter = {
    #     'malwareType': ['网站后门', '恶意进程'],
    #     'malwareSubtype': ['WEBSHELL', '挖矿程序'],
    #     'fileType': ['BIN', 'WEBSHELL']
    # }

    # 时间片为空的逻辑，以确定where_str
    if slice:
        begin_time_number = slice['beginTime']
        end_time_number = slice['endTime']
        begin_timestamp, end_timestamp = get_timestamp(begin_time_number, end_time_number)
        where_str = get_slice_where_str(begin_timestamp, end_timestamp)
    else:
        begin_time_number = 0
        where_str = ''

    t1 = time.time()
    cursor = connection.cursor()
    cursor.execute("select `source`, target, similarity from similarity_info " + where_str)
    desc = cursor.description
    all_data = cursor.fetchall()
    row_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]


    t2 = time.time()
    # 读取file_detail_info
    with open(str(BASE_DIR) + '//backend//data//file_detail_info.json', 'r', encoding='utf8')as fp:
        file_detail_info = json.load(fp)

    row_nodes = []
    row_links = []
    row_nodes_set = set()
    row_links_set = set()

    has_filter = has_filter_func(file_filter)

    # 先得到节点
    for r in row_data:
        source = r['source']
        target = r['target']
        # 文件过滤
        if has_filter:
            if (file_detail_info[source]['malware_class'] in file_filter['malwareSubtype'] or
                file_detail_info[source][
                    'malware_type'] in file_filter['malwareSubtype'] or file_detail_info[source]['file_type'] in \
                file_filter['fileType']) and (file_detail_info[target]['malware_class'] in file_filter[
                'malwareSubtype'] or file_detail_info[target]['malware_type'] in file_filter['malwareSubtype'] or \
                                              file_detail_info[target]['file_type'] in file_filter['fileType']):
                if source not in row_nodes_set:
                    row_nodes.append({
                        "id": source,
                        "file_type": file_detail_info[source]['malware_type'],
                        "ecsId": file_detail_info[source]['ESC_ID'],
                        "asId": file_detail_info[source]['AS_ID'],
                        "vpcId": file_detail_info[source]['VPC_ID'],
                        "regionId": file_detail_info[source]['Region_ID'],
                        "createTIme": file_detail_info[source]['create_time']
                    })
                    row_nodes_set.add(source)

                if target not in row_nodes_set:
                    row_nodes.append({
                        "id": target,
                        "file_type": file_detail_info[target]['malware_type'],
                        "ecsId": file_detail_info[target]['ESC_ID'],
                        "asId": file_detail_info[target]['AS_ID'],
                        "vpcId": file_detail_info[target]['VPC_ID'],
                        "regionId": file_detail_info[target]['Region_ID'],
                        "createTIme": file_detail_info[target]['create_time']
                    })
                    row_nodes_set.add(target)
        else:
            if source not in row_nodes_set:
                row_nodes.append({
                    "id": source,
                    "file_type": file_detail_info[source]['malware_type'],
                    "ecsId": file_detail_info[source]['ESC_ID'],
                    "asId": file_detail_info[source]['AS_ID'],
                    "vpcId": file_detail_info[source]['VPC_ID'],
                    "regionId": file_detail_info[source]['Region_ID'],
                    "createTIme": file_detail_info[source]['create_time']
                })
                row_nodes_set.add(source)

            if target not in row_nodes_set:
                row_nodes.append({
                    "id": target,
                    "file_type": file_detail_info[target]['malware_type'],
                    "ecsId": file_detail_info[target]['ESC_ID'],
                    "asId": file_detail_info[target]['AS_ID'],
                    "vpcId": file_detail_info[target]['VPC_ID'],
                    "regionId": file_detail_info[target]['Region_ID'],
                    "createTIme": file_detail_info[target]['create_time']
                })
                row_nodes_set.add(target)

    t25 = time.time()
    # 边数设置为1000？
    edge_number = len(row_data)
    if edge_number > 1000:
        # 当边数大于1000时，随机取节点数一半条边
        count = 0
        while count < len(row_nodes) / 2:
            index = random.randint(0, edge_number - 1)
            rd = row_data[index]
            if index not in row_links_set:
                row_links.append({
                    "source": rd['source'],
                    "target": rd['target'],
                    "similarity": rd['similarity'],
                    "isLoop": False
                })
                count += 1

        data = {
            "isCorrect": True,
            "nodes": row_nodes,
            "links": row_links
        }

    else:
        # 当边数小于1000时
        for r in row_data:
            source = r['source']
            target = r['target']
            if source in row_nodes_set and target in row_nodes_set:
                if (source, target) not in row_links_set:
                    row_links.append({
                        "source": source,
                        "target": target,
                        "similarity": r['similarity'],
                        "isLoop": True
                    })

        data = {
            "isCorrect": False,
            "nodes": row_nodes,
            "links": row_links
        }

        # 按相似度=1的聚类，放在一个集合中
        set_list = []
        for ln in data['links']:
            if float(ln['similarity']) == 1:
                is_in = False
                for s in set_list:
                    if ln['source'] in s:
                        s.add(ln['target'])
                        is_in = True
                        break
                    if ln['target'] in s:
                        s.add(ln['source'])
                        is_in = True
                        break

                if not is_in:
                    set_list.append(set())
                    set_list[len(set_list) - 1].add(ln['source'])
                    set_list[len(set_list) - 1].add(ln['target'])

        set_list_after_handle = []
        for s in set_list:
            set_list_after_handle.append(list(s))
        links_after_handle = []
        links_set = set()

        # 对每个集合生成一个环
        for s in set_list_after_handle:
            for i in range(len(s) - 1):
                links_after_handle.append({
                    "source": s[i],
                    "target": s[i + 1],
                    "similarity": 1.0,
                    "isLoop": True
                })
                links_set.add((s[i], s[i + 1]))
                links_set.add((s[i + 1], s[i]))

            links_after_handle.append({
                "source": s[0],
                "target": s[len(s) - 1],
                "similarity": 1.0,
                "isLoop": True
            })
            links_set.add((s[0], s[len(s) - 1]))
            links_set.add((s[len(s) - 1], s[0]))

        # 再生成除环以外的边
        for le in data['links']:
            # 判断两者不在一个集合内
            source = le['source']
            target = le['target']

            is_in_set = False
            for s in set_list:
                if source in s and target in s:
                    is_in_set = True

            if not is_in_set:
                if (le['source'], le['target']) not in links_set:
                    links_after_handle.append({
                        "source": le['source'],
                        "target": le['target'],
                        "similarity": float(le['similarity']),
                        "isLoop": False
                    })
        data['links'] = links_after_handle

    t3 = time.time()
    ReturnData = data
    # print(t1 - t0)
    # print(t2 - t1)
    # print(t25 - t2)
    # print(t3 - t2)
    # print(t4 - t3)
    # print(t5 - t4)
    # print(len(data['links']))
    return HttpResponse(json.dumps(ReturnData), content_type='application/json')
