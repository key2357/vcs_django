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


# 取文件信息
def ge_tree(fr_now_node, fr_iteration, parent, file_uuid_md5_info):
    if fr_iteration:
        for frkey in fr_iteration:
            if parent == '':
                fr_now_node.append({
                    'name': frkey,
                })
            else:
                str_key = frkey + '|' + parent
                fr_now_node.append({
                    'uuid': file_uuid_md5_info[str_key]['uuid'],
                    'file_md5': file_uuid_md5_info[str_key]['file_md5'],
                    'name': frkey,
                    'caller': file_uuid_md5_info[str_key]['caller'],
                    'argc': file_uuid_md5_info[str_key]['argc'],
                    'argv': file_uuid_md5_info[str_key]['argv'],
                    'return': file_uuid_md5_info[str_key]['return'],
                    'index': file_uuid_md5_info[str_key]['index'],
                    'dynamic': file_uuid_md5_info[str_key]['dynamic'],
                    'call_num': file_uuid_md5_info[str_key]['call_num'],
                    'dynamic_index': file_uuid_md5_info[str_key]['dynamic_index'],
                    'all_index': file_uuid_md5_info[str_key]['all_index'],
                    'df': file_uuid_md5_info[str_key]['df']
                })

            if fr_iteration[frkey]:
                fr_now_node[len(fr_now_node) - 1]['children'] = []
                const_fr_now_node = fr_now_node[len(fr_now_node) - 1]['children']
                const_fr_iteration = fr_iteration[frkey]
                const_parent = frkey
                ge_tree(const_fr_now_node, const_fr_iteration, const_parent, file_uuid_md5_info)

    return fr_now_node, fr_iteration


# import matplotlib.pyplot as plt
# 13903 373668
def test(request):
    # 测试一个uuid-md5
    cursor = connection.cursor()
    cursor.execute("select uuid, file_md5, `name`, `caller`, argc, argv, `return`, `index`, dynamic "
                   "from malware_op_code where uuid = 'ac6440efd0d224d0437c2e56bba9a789' and "
                   "file_md5 = 'fcee6226d09d150bfa5f103bee61fbde' and `name` = 'htmlspecialchars' and caller = 'eval'")

    desc = cursor.description
    all_data = cursor.fetchall()
    ecs_force_and_file = [dict(zip([col[0] for col in desc], row)) for row in all_data]
    for e in ecs_force_and_file:
        print(e["index"])

    # name = ['uuid', 'file_md5', 'index']
    # test = pd.DataFrame(columns=name, data=ecs_force_and_file)
    # test.to_csv('./example.csv')

    # 读取opcode_example_result.csv
    df = pd.read_csv(str(BASE_DIR) + '//opcode_example_result.csv', usecols=[1, 2])
    data_color = df.iloc[:, 0:2].values
    data_color_list = []
    for i in range(len(data_color)):
        data_color_list.append({
            'uuid': data_color[i][0],
            'file_md5': data_color[i][1]
        })

    for index in range(5, 6):
        # 取opcode 其中dynamic里面不要全是0的，然后数据量大一点。然后一个文件下caller去重后种类多一点的。加一个字段order
        cursor = connection.cursor()
        cursor.execute("select uuid, file_md5, `name`, `caller`, argc, argv, `return`, `index`, dynamic "
                       "from malware_op_code where uuid = '{0}' and file_md5 = '{1}'".format(
            data_color_list[index]['uuid'],
            data_color_list[index][
                'file_md5']))
        print(data_color_list[index]['uuid'], data_color_list[index]['file_md5'])
        desc = cursor.description
        all_data = cursor.fetchall()
        ecs_force_and_file = [dict(zip([col[0] for col in desc], row)) for row in all_data]

        edge_dict = {}
        for e in ecs_force_and_file:
            str_key = e['name'] + e['caller'] + e['argc']

            dynamic = e['dynamic']
            dynamic_array = dynamic[1:len(dynamic) - 1].split(',')
            dynamic_handle = []
            dynamic_index = []
            argc = int(e['argc'])

            if str_key not in edge_dict:
                all_index = []
                all_index.append(e['index'])
                for d in dynamic_array:
                    if d == '':
                        d = 0
                    dynamic_handle.append(int(d))
                    if int(d) != 0:
                        dynamic_index.append([int(e['index'])])
                    else:
                        dynamic_index.append([])

                if int(argc) > len(dynamic_array):
                    for i in range(int(argc - len(dynamic_array))):
                        dynamic_handle.append(0)
                        dynamic_index.append([])

                edge_dict[str_key] = {
                    'uuid': e['uuid'],
                    'file_md5': e['file_md5'],
                    'name': e['name'],
                    'caller': e['caller'],
                    'argc': e['argc'],
                    'argv': e['argv'],
                    'return': e['return'],
                    'index': int(e['index']),
                    'dynamic': dynamic_handle,
                    'call_num': 1,
                    'dynamic_index': dynamic_index,
                    'all_index': all_index,
                    'df': 0,
                }

            else:
                # 比较
                for d in dynamic_array:
                    if d == '':
                        d = 0
                    dynamic_handle.append(int(d))

                if int(argc) > len(dynamic_array):
                    for i in range(int(argc - len(dynamic_array))):
                        dynamic_handle.append(0)

                old_dynamic = edge_dict[str_key]['dynamic']

                if e['index'] not in edge_dict[str_key]['all_index']:
                    edge_dict[str_key]['all_index'].append(e['index'])

                for i in range(len(dynamic_handle)):
                    if old_dynamic[i] == 0 and dynamic_handle[i] > 0:
                        edge_dict[str_key]['df'] = 1
                        edge_dict[str_key]['dynamic_index'][i].append(int(e['index']))

                    elif old_dynamic[i] > 0 and dynamic_handle[i] == 0:
                        edge_dict[str_key]['df'] = 1

                edge_dict[str_key]['call_num'] += 1
                if int(e['index']) < int(edge_dict[str_key]['index']):
                    edge_dict[str_key]['index'] = int(e['index'])

        result_data = []
        for ekey in edge_dict:
            result_data.append(edge_dict[ekey])

        result_data = sorted(result_data, key=lambda x: x['index'])

        name = ['uuid', 'file_md5', 'name', 'caller', 'argc', 'argv', 'return',
                'index', 'dynamic', 'call_num', 'dynamic_index', 'all_index', 'df']
        test = pd.DataFrame(columns=name, data=result_data)
        test.to_csv('./opcode_example/aa_opcode_example_' + str(index) + '.csv', index=0)

    # for index in range(50):
    #     df = pd.read_csv(str(BASE_DIR) + '//opcode_example//opcode_example_' + str(int(index)) + '.csv', usecols=[2, 3])
    #     data_color = df.iloc[:, 0:2].values
    #     edge_set = set()
    #     for i in range(len(data_color)):
    #         edge_set.add((data_color[i][0], data_color[i][1]))
    #
    #     # u_set 保存的点  e_set 保存的边
    #     u_set = set()
    #     u_set.add('__main__')
    #     e_set_dict = {}
    #     # 先以__main__为起点
    #     # 一层一层
    #
    #     old_order = set()
    #     for e in edge_set:
    #         str_key = e[1] + '|' + e[0]
    #         if e[1] == '__main__' and e[0] != '__main__':
    #             old_order.add(e[0])
    #             e_set_dict[str_key] = 0
    #
    #     count = 1
    #     is_continue = True
    #     while is_continue:
    #         before_len = len(e_set_dict)
    #         new_order = set()
    #         for e in edge_set:
    #             str_key = e[1] + '|' + e[0]
    #             if str_key not in e_set_dict and e[1] in old_order and e[0] != e[1]:
    #                 new_order.add(e[0])
    #                 e_set_dict[str_key] = count
    #         after_len = len(e_set_dict)
    #         if before_len == after_len:
    #             is_continue = False
    #             e_set_dict['order_deep'] = count
    #         old_order = new_order
    #         count += 1
    #
    #     result_tree = {
    #         '__main__': {},
    #     }
    #
    #     for i in range(e_set_dict['order_deep']):
    #         for ekey in e_set_dict:
    #             if e_set_dict[ekey] == i:
    #
    #                 key_array = ekey.split('|')
    #                 caller = key_array[0]
    #                 name = key_array[1]
    #
    #                 # 回溯
    #                 deep_now = e_set_dict[ekey]
    #                 trap = [name, caller]
    #
    #                 while caller != '__main__':
    #                     deep_now -= 1
    #                     for eekey in e_set_dict:
    #                         if eekey != 'order_deep':
    #                             key_array = eekey.split('|')
    #                             e_caller = key_array[0]
    #                             e_name = key_array[1]
    #
    #                             if e_name == caller and e_set_dict[eekey] == deep_now:
    #                                 caller = e_caller
    #                                 trap.append(caller)
    #
    #                 # 确定到父节点
    #                 parent = result_tree
    #                 if len(trap) == 2:
    #                     print(index)
    #                     parent['__main__'][trap[0]] = {}
    #                 else:
    #                     for ii in range(len(trap) - 1, 0, -1):
    #                         parent = parent[trap[ii]]
    #                     parent[trap[0]] = {}
    #
    #     # 读取信息
    #     df = pd.read_csv(str(BASE_DIR) + '//opcode_example//opcode_example_' + str(int(index)) + '.csv',
    #                      usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    #
    #     data_color = df.iloc[:, 0:13].values
    #     data_color_dict = {}
    #     for i in range(len(data_color)):
    #         str_key = data_color[i][2] + '|' + data_color[i][3]
    #         data_color_dict[str_key] = {
    #             'uuid': data_color[i][0],
    #             'file_md5': data_color[i][1],
    #             'name': data_color[i][2],
    #             'caller': data_color[i][3],
    #             'argc': data_color[i][4],
    #             'argv': data_color[i][5],
    #             'return': data_color[i][6],
    #             'index': data_color[i][7],
    #             'dynamic': data_color[i][8],
    #             'call_num': data_color[i][9],
    #             'dynamic_index': data_color[i][10],
    #             'all_index': data_color[i][11],
    #             'df': data_color[i][12]
    #         }
    #
    #     file_uuid_md5_info = data_color_dict
    #     another_tree = []
    #     if result_tree:
    #         now_node = another_tree
    #         iteration = result_tree
    #         parent = ''
    #         ge_tree(now_node, iteration, parent, file_uuid_md5_info)
    #
    #     json_data = json.dumps(another_tree)
    #     json_data = json_data[1:len(json_data) - 1]
    #     file_object = open('./opcode_tree/opcode_example_' + str(int(index) + 1) + '.json', 'w')
    #     file_object.write(json_data)
    #     file_object.close()

    # order_3 = set()
    # for e in edge_set:
    #     str_key = e[1] + '|' + e[0]
    #     if str_key not in e_set_dict and e[1] in order_2:
    #         e_set_dict[str_key] = 2
    #
    # for e in edge_set:
    #     str_key = e[1] + '|' + e[0]
    #     if str_key not in e_set_dict and e[1] in order_3:
    #         e_set_dict[str_key] = 3

    # order_4 = set()
    # for e in edge_set:
    #     if e[1] in order_3 and e[0] not in u_set:
    #         order_4.add(e[0])
    #         u_set.add(e[0])

    #
    # print(len(order_4), len(order_3), len(order_2), len(order_1))

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
    #     'beginTime': 0.5,
    #     'endTime': 0.6
    # }
    #
    # file_filter = {
    #     'malwareType': ['网站后门', '恶意进程'],
    #     'malwareSubtype': ['WEBSHELL', '挖矿程序'],
    #     'fileType': ['BIN', 'WEBSHELL']
    # }
    #
    # file = {
    #     'categories': 'malwareSubtype',
    #     'subtype': 'WEBSHELL'
    # }

    # change file
    # file = change_file(file)

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
        "count(malware_type) AS malwareNumber, "
        "sum(case when malware_type='WEBSHELL'then 1 else 0 end) as WEBSHELL, "
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
        "sum(case when malware_type='自变异木马' then 1 else 0 end) as 自变异木马, "
        "sum(case when malware_class='网站后门' then 1 else 0 end) as 网站后门, "
        "sum(case when malware_class='恶意进程' then 1 else 0 end) as 恶意进程, "
        "sum(case when malware_class='恶意脚本' then 1 else 0 end) as 恶意脚本 "
        "from malware_base_info AS a LEFT JOIN user_netstate_info AS b ON a.uuid=b.ECS_ID " + where_str + " group by uuid")

    desc = cursor.description
    all_data = cursor.fetchall()
    ecs_force_and_file = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    # 再取出所有的ECS
    cursor.execute("select ECS_ID AS ESC_ID, AS_ID, VPC_ID, Region_ID from user_netstate_info")
    desc = cursor.description
    all_data = cursor.fetchall()
    all_ecs = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    # 先判断ecs_force_and_file中的ecs
    ecs_set = set()
    for e in ecs_force_and_file:
        ecs_set.add(e['ESC_ID'])

    for a in all_ecs:
        if a['ESC_ID'] not in ecs_set:
            ecs_force_and_file.append({
                'ESC_ID': a['ESC_ID'],
                'AS_ID': a['AS_ID'],
                'VPC_ID': a['VPC_ID'],
                'Region_ID': a['Region_ID'],
                'malwareNumber': 0,
                'WEBSHELL': 0,
                'DDOS木马': 0,
                '被污染的基础软件': 0,
                '恶意程序': 0,
                '恶意脚本文件': 0,
                '感染型病毒': 0,
                '黑客工具': 0,
                '后门程序': 0,
                '勒索病毒': 0,
                '漏洞利用程序': 0,
                '木马程序': 0,
                "蠕虫病毒": 0,
                "挖矿程序": 0,
                "自变异木马": 0,
                "网站后门": 0,
                "恶意进程": 0,
                "恶意脚本": 0,
            })

    # if not ecs_force_and_file:
    #     ReturnData = {}
    #     return HttpResponse(json.dumps(ReturnData), content_type='application/json')

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
    if file['categories'] != '' and file['subtype'] != '':
        categories = file['categories']
        subtype = file['subtype']
        for d in ecs_force_and_file:
            if categories == 'FileType':
                if subtype == 'Webshell':
                    subtype = 'WEBSHELL'
                elif subtype == '二进制':
                    subtype = '恶意进程'
                else:
                    subtype = '恶意脚本'
                if d[subtype] > 0:
                    is_highlight.append(True)
                else:
                    is_highlight.append(False)
            else:
                if d[subtype] > 0:
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

    # allData 里面每个region排序
    for i in range(len(allData)):
        region = sorted(allData[i]['Region_VPC'], key=lambda x: x['ECS_NUM'], reverse=1)
        allData[i]['Region_VPC'] = region
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
    #     'malwareType': [],
    #     'malwareSubtype': [],
    #     'fileType': []
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

    cursor = connection.cursor()
    cursor.execute("select `source`, target, similarity from similarity_info " + where_str)
    desc = cursor.description
    all_data = cursor.fetchall()
    row_data = [dict(zip([col[0] for col in desc], row)) for row in all_data]

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

    ReturnData = data
    return HttpResponse(json.dumps(ReturnData), content_type='application/json')
