from backend.config import INIT_TIME, FINAL_TIME, SENSITIVE_FUNC
from django.db import connection
import datetime
import numpy as np


# 文件过滤
def get_file_where_str(malware_type_list, malware_subtype_list, malware_filetype_list):
    where_str = ''
    malware_type_str = '\',\''.join(malware_type_list)
    malware_subtype_str = '\',\''.join(malware_subtype_list)
    malware_filetype_str = '\',\''.join(malware_filetype_list)
    is_first = True
    if malware_type_str != '':
        if is_first:
            where_str = 'where malware_class in (\'' + malware_type_str + '\') '
            is_first = False
        else:
            where_str += 'and malware_class in (\'' + malware_type_str + '\') '

    if malware_subtype_str != '':
        if is_first == 0:
            where_str = 'where malware_type in (\'' + malware_subtype_str + '\') '
            is_first = False
        else:
            where_str += 'and malware_type in (\'' + malware_subtype_str + '\') '

    if malware_filetype_str != '':
        if is_first == 0:
            where_str = 'where file_type in (\'' + malware_filetype_str + '\') '
            is_first = False
        else:
            where_str += 'and file_type in (\'' + malware_filetype_str + '\') '
    return where_str


# 文件 + 时间 过滤
def get_file_and_time_where_str(malware_type_list, malware_subtype_list, malware_filetype_list, begin_time_str,
                                end_time_str):
    where_str = ''
    malware_type_str = '\',\''.join(malware_type_list)
    malware_subtype_str = '\',\''.join(malware_subtype_list)
    malware_filetype_str = '\',\''.join(malware_filetype_list)

    where_str = 'where create_time > \'' + begin_time_str + '\' and create_time < \'' + end_time_str + '\' '

    if malware_type_str != '':
        where_str += 'and malware_class in (\'' + malware_type_str + '\') '

    if malware_subtype_str != '':
        where_str += 'and malware_type in (\'' + malware_subtype_str + '\') '

    if malware_filetype_str != '':
        where_str += 'and file_type in (\'' + malware_filetype_str + '\') '

    return where_str


# 0-1 映射到一个time_str
def get_time_str(begin_time_number, end_time_number):
    # 先将number转为时间戳
    begin_time_stamp = begin_time_number * (FINAL_TIME - INIT_TIME) + INIT_TIME
    end_time_number = end_time_number * (FINAL_TIME - INIT_TIME) + INIT_TIME
    begin_time_array = datetime.datetime.fromtimestamp(begin_time_stamp)
    end_time_array = datetime.datetime.fromtimestamp(end_time_number)
    begin_time_str = str(begin_time_array.strftime("%Y-%m-%d %H:%M:%S"))
    end_time_str = str(end_time_array.strftime("%Y-%m-%d %H:%M:%S"))
    return begin_time_str, end_time_str


def get_time_where_str(begin_time_str, end_time_str):
    where_str = 'where create_time > \'' + begin_time_str + '\' and create_time < \'' + end_time_str + '\' '
    return where_str


def get_slice_where_str(begin_time_str, end_time_str):
    where_str = 'where source_create_time > \'' + str(begin_time_str) + '\' and source_create_time < \'' + str(
        end_time_str) + '\' and target_create_time > \'' + str(begin_time_str) + '\' and target_create_time < \'' + str(
        end_time_str) + '\' '
    return where_str


def get_timestamp(begin_time_number, end_time_number):
    begin_timestamp = begin_time_number * (FINAL_TIME - INIT_TIME) + INIT_TIME
    end_timestamp = end_time_number * (FINAL_TIME - INIT_TIME) + INIT_TIME
    return begin_timestamp, end_timestamp


def has_filter_func(file_filter):
    if file_filter['malwareType'] or file_filter['malwareSubtype'] or file_filter['fileType']:
        has_filter = True
    else:
        has_filter = False
    return has_filter


def get_vpc_score_info(vpc, max_info):
    malware_sub_type = set()
    malware_type = set()
    file_num = []
    for az in vpc['AS_ECS']:
        for ecs in az['AS_ECS_TYPE']:
            file_num.append(ecs['ecsFileNum'])
            for mt in ecs['malware_type']:
                malware_type.add(mt)
            for ms in ecs['malware_subtype']:
                malware_sub_type.add(ms)

    # 计算大类类型数
    malware_type_num = len(malware_type) / 3
    # 计算小类类型数
    malware_sub_type_num = len(malware_sub_type) / 14
    # 计算文件总数：
    file_total = 0
    for fn in file_num:
        file_total += fn

    # 计算文件标准差
    np_file_num = np.array(file_num)
    std_data = np.std(np_file_num)

    score_info = [file_total, malware_type_num, malware_sub_type_num, std_data]
    if file_total > max_info[0]:
        max_info[0] = file_total
    if malware_type_num > max_info[1]:
        max_info[1] = malware_type_num
    if malware_sub_type_num > max_info[2]:
        max_info[2] = malware_sub_type_num
    if std_data > max_info[3]:
        max_info[3] = std_data
    return score_info, max_info


def get_vpc_score(score_info, alpha, beta, theta, gamma, max_info):
    a = 0
    if max_info[0] != 0:
        a = alpha * score_info[0] / max_info[0]
    b = 0
    if max_info[1] != 0:
        b = beta * score_info[1] / max_info[1]
    c = 0
    if max_info[2] != 0:
        c = theta * score_info[2] / max_info[2]
    d = 0
    if max_info[3] != 0:
        d = gamma * score_info[3] / max_info[3]
    return a + b + c + d


def get_time_str_by_time_type(time_type):
    if time_type == 'all':
        begin_time_str, end_time_str = get_time_str(0, 1)
    elif time_type == '7 days':
        begin_time_str = '2020-10-27 00-00-00'
        end_time_str = '2020-11-03 00-00-00'
    elif time_type == '1 month':
        begin_time_str = '2020-10-03 00-00-00'
        end_time_str = '2020-11-03 00-00-00'
    elif time_type == '1 year':
        begin_time_str = '2019-11-03 00-00-00'
        end_time_str = '2020-11-03 00-00-00'
    else:
        begin_time_str, end_time_str = get_time_str(0, 1)
    return begin_time_str, end_time_str


# 生成opcode_example csv格式  依赖读取opcode_example_result
def generate_opcode_csv(uuid, file_md5):
    # 加一个字段order
    cursor = connection.cursor()
    cursor.execute("select uuid, file_md5, `name`, `caller`, argc, argv, `return`, `index`, dynamic "
                   "from malware_op_code where file_md5 = '{0}' and uuid = '{1}' ".format(file_md5, uuid))
    desc = cursor.description
    all_data = cursor.fetchall()
    ecs_force_and_file = [dict(zip([col[0] for col in desc], row)) for row in all_data]

    # 读敏感函数文件
    sensitive_set = set(SENSITIVE_FUNC)

    # 将index int化
    for ef in ecs_force_and_file:
        ef['index'] = int(ef['index'])

    # 按index排序
    ecs_force_and_file = sorted(ecs_force_and_file, key=lambda value: value['index'], reverse=True)

    # 生成tuple
    index_tuple = []
    for ef in ecs_force_and_file:
        index_tuple.append(ef['caller'] + ef['name'])

    # 计算周期性
    periodicity_count = msv_periodicity(index_tuple)

    func_periodicity = {}
    for ei in range(len(ecs_force_and_file)):
        ef = ecs_force_and_file[ei]
        if ef['caller'] + ef['name'] not in func_periodicity:
            func_periodicity[ef['caller'] + ef['name']] = periodicity_count[ei]

    edge_dict = {}
    for e in ecs_force_and_file:
        str_key = e['name'] + e['caller'] + e['argc']

        dynamic = e['dynamic']
        dynamic_array = dynamic[1:len(dynamic) - 1].split(',')
        dynamic_handle = []
        dynamic_index = []
        argc = int(e['argc'])

        # 查看是否为敏感函数
        if e['name'] in sensitive_set:
            is_sensitive = True
        else:
            is_sensitive = False

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
                # 'argv': e['argv'],
                # 'return': e['return'],
                'index': int(e['index']),
                'dynamic': dynamic_handle,
                'call_num': 1,
                'dynamic_index': dynamic_index,
                'all_index': all_index,
                'df': 0,
                'period': func_periodicity[e['caller'] + e['name']],
                'is_sensitive': is_sensitive
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
                    edge_dict[str_key]['dynamic'][i] = dynamic_handle[i]
                elif old_dynamic[i] > 0 and dynamic_handle[i] == 0:
                    edge_dict[str_key]['df'] = 1

            edge_dict[str_key]['call_num'] += 1
            if int(e['index']) < int(edge_dict[str_key]['index']):
                edge_dict[str_key]['index'] = int(e['index'])

    result_data = []
    for ekey in edge_dict:
        result_data.append(edge_dict[ekey])

    result_data = sorted(result_data, key=lambda x: x['index'])

    return result_data


# 生成tree.json 的迭代函数
def ge_tree(fr_now_node, fr_iteration, parent, file_uuid_md5_info, unique):
    if fr_iteration:
        for frkey in fr_iteration:
            if parent == '':
                fr_now_node.append({
                    'name': frkey,
                    'unique_id': unique
                })
            else:
                fr_key_array = frkey.split('|')
                if len(fr_key_array) > 1:
                    frkey = fr_key_array[0]
                str_key = frkey + '|' + parent
                fr_now_node.append({
                    'uuid': file_uuid_md5_info[str_key]['uuid'],
                    'file_md5': file_uuid_md5_info[str_key]['file_md5'],
                    'name': frkey,
                    'caller': file_uuid_md5_info[str_key]['caller'],
                    'argc': int(file_uuid_md5_info[str_key]['argc']),
                    # 'argv': file_uuid_md5_info[str_key]['argv'],
                    # 'return': file_uuid_md5_info[str_key]['return'],
                    'index': file_uuid_md5_info[str_key]['index'],
                    'dynamic': file_uuid_md5_info[str_key]['dynamic'],
                    'call_num': file_uuid_md5_info[str_key]['call_num'],
                    'dynamic_index': file_uuid_md5_info[str_key]['dynamic_index'],
                    'all_index': file_uuid_md5_info[str_key]['all_index'],
                    'df': file_uuid_md5_info[str_key]['df'],
                    'period': file_uuid_md5_info[str_key]['period'],
                    'is_sensitive': file_uuid_md5_info[str_key]['is_sensitive']
                })

            if frkey in fr_iteration:
                if fr_iteration[frkey]:
                    fr_now_node[len(fr_now_node) - 1]['children'] = []
                    const_fr_now_node = fr_now_node[len(fr_now_node) - 1]['children']
                    const_fr_iteration = fr_iteration[frkey]
                    const_parent = frkey
                    ge_tree(const_fr_now_node, const_fr_iteration, const_parent, file_uuid_md5_info, unique)

    return fr_now_node, fr_iteration


# 生成tree.json 依赖 opcode_example csv格式
def generate_opcode_tree(opcode_csv, tree_type):
    # 迭代读取csv格式的opcode_example
    data_color = []
    for o in opcode_csv:
        data_color.append([o['name'], o['caller']])

    # edge_set 保存原始边信息
    edge_set = set()
    for i in range(len(data_color)):
        edge_set.add((data_color[i][0], data_color[i][1]))

    # u_set 已添加的点
    u_set = set()
    # 初始化u集
    u_set.add('__main__')
    # e_set_dict保存以边作为key，order作value
    e_set_dict = {}

    # 先以a为起点 一层一层广度遍历
    old_order = set()
    order_width = 0  # 保存order最大宽度
    for e in edge_set:
        str_key = e[1] + '|' + e[0]
        if e[1] == '__main__':
            old_order.add(e[0])
            e_set_dict[str_key] = 0

    if len(old_order) > order_width:
        order_width = len(old_order)

    count = 1
    is_continue = True
    while is_continue:
        before_len = len(e_set_dict)
        new_order = set()
        for e in edge_set:
            str_key = e[1] + '|' + e[0]
            if str_key not in e_set_dict and e[1] in old_order:
                new_order.add(e[0])
                e_set_dict[str_key] = count
        after_len = len(e_set_dict)
        if before_len == after_len:
            is_continue = False
            e_set_dict['order_deep'] = count
        old_order = new_order
        if len(old_order) > order_width:
            order_width = len(old_order)
        count += 1

    result_tree = {
        '__main__': {},
    }

    # 生成树，核心算法，递归实现
    for i in range(e_set_dict['order_deep']):
        now_nodes = set()
        for ekey in e_set_dict:
            if e_set_dict[ekey] == i:
                key_array = ekey.split('|')
                caller = key_array[0]
                name = key_array[1]

                if name not in now_nodes:
                    now_nodes.add(name)
                else:
                    name = name + '|' + 'df'
                    now_nodes.add(name)

                # 回溯
                deep_now = e_set_dict[ekey]
                trap = [name, caller]

                while caller != '__main__':
                    deep_now -= 1
                    for eekey in e_set_dict:
                        if eekey != 'order_deep':
                            key_array = eekey.split('|')
                            e_caller = key_array[0]
                            e_name = key_array[1]

                            if e_name == caller and e_set_dict[eekey] == deep_now:
                                caller = e_caller
                                trap.append(caller)
                                break

                # 不确定父节点，直接上
                parent_oo = result_tree
                for ii in range(len(trap) - 1, -1, -1):
                    if trap[ii] not in parent_oo:
                        parent_oo[trap[ii]] = {}
                    else:
                        parent_oo = parent_oo[trap[ii]]

    # 读取信息 转变为接口格式
    data_color = []
    for r in opcode_csv:
        data_color.append([r['uuid'], r['file_md5'], r['name'], r['caller'], r['argc'], 'argv', 'return', r['index'], str(r['dynamic']), r['call_num'], str(r['dynamic_index']), str(r['all_index']), r['df'], r['period'], r['is_sensitive']])
    data_color_dict = {}

    # 计算污点类型和污点数量
    dynamic_type = 0
    dynamic_type_set = set()
    dynamic_num = 0
    for i in range(len(data_color)):
        dynamic_array = data_color[i][8][1:len(data_color[i][8]) - 1].split(',')
        for dy in dynamic_array:
            if int(dy) != 0:
                if int(dy) not in dynamic_type_set:
                    dynamic_type += 1
                    dynamic_type_set.add(int(dy))
                dynamic_num += 1
        str_key = data_color[i][2] + '|' + data_color[i][3]
        data_color_dict[str_key] = {
            'uuid': data_color[i][0],
            'file_md5': data_color[i][1],
            'name': data_color[i][2],
            'caller': data_color[i][3],
            'argc': data_color[i][4],
            # 'argv': data_color[i][5],
            # 'return': data_color[i][6],
            'index': data_color[i][7],
            'dynamic': data_color[i][8],
            'call_num': data_color[i][9],
            'dynamic_index': data_color[i][10],
            'all_index': data_color[i][11],
            'df': data_color[i][12],
            'period': data_color[i][13],
            'is_sensitive': data_color[i][14]
        }

    file_uuid_md5_info = data_color_dict
    another_tree = []
    if result_tree:
        now_node = another_tree
        iteration = result_tree
        parent = ''
        ge_tree(now_node, iteration, parent, file_uuid_md5_info, opcode_csv[0]['uuid'] + opcode_csv[0]['file_md5'])

    if tree_type == 'stain':
        stack_dynamic = []
        stain_tree = {
            "name": "__main__",
            "unique_id": another_tree[0]['unique_id'],
            "children": []
        }
        another_tree = [generate_stain_tree(another_tree[0]['children'], stack_dynamic, stain_tree)]

    return another_tree


# 生成污点树
def generate_stain_tree(tree, stack_dynamic, stain_tree):
    for c in tree:
        print(c)
        dynamic = c['dynamic']
        dynamic_array = dynamic[1: len(dynamic) - 1].split(',')

        # 做是否污染判断
        is_dynamic = False
        for d in dynamic_array:
            if int(d) != 0:
                is_dynamic = True

        # 做敏感函数判断
        is_sensitive = c['is_sensitive']

        is_important = 0
        if is_dynamic or is_sensitive:
            is_important = 1

        stack_dynamic.append(is_important)
        if is_important:
            for si in range(len(stack_dynamic)):
                stack_dynamic[si] = 1

        stain_tree['children'].append({
            'uuid': c['uuid'],
            'file_md5': c['file_md5'],
            "name": c['name'],
            "caller": c['caller'],
            "argc": c['argc'],
            "index": c['index'],
            "dynamic": c['dynamic'],
            "call_num": c['call_num'],
            "dynamic_index": c['dynamic_index'],
            "all_index": c['all_index'],
            "df": c['df'],
            "period": c['period'],
            "is_sensitive": c['is_sensitive'],
        })

        if 'children' in c:
            const_tree = c['children']
            stain_tree['children'][len(stain_tree['children']) - 1]['children'] = []
            const_stain_tree = stain_tree['children'][len(stain_tree['children']) - 1]

            generate_stain_tree(const_tree, stack_dynamic, const_stain_tree)

        is_stain = stack_dynamic[len(stack_dynamic) - 1]
        if not is_stain:
            stain_tree['children'].pop()
        stack_dynamic.pop()
    return stain_tree


# 栈结构方法
def find_max_dynamic_deep(children_list, stack_dynamic, dynamic_max):
    for c in children_list:
        dynamic = c['dynamic']
        dynamic_array = dynamic[1: len(dynamic) - 1].split(',')

        # 做是否污染判断
        dynamic_index = []
        for d in dynamic_array:
            if int(d) != 0 and d not in dynamic_index:
                dynamic_index.append(int(d))
                # is_dynamic = True

        stack_dynamic.append(dynamic_index)
        stack_index = stack_dynamic[len(stack_dynamic) - 1]

        if stack_index:
            for index in stack_index:
                temp_max = 1
                for i in range(len(stack_dynamic) - 2, -1, -1):
                    if index in stack_dynamic[i]:
                        temp_max += 1
                    else:
                        break
                if temp_max > dynamic_max:
                    dynamic_max = temp_max

                # if temp_max > 1:
                #     print(c['caller'] + '|' + c['name'])

        if 'children' in c:
            const_children_list = c['children']
            dynamic_max = find_max_dynamic_deep(const_children_list, stack_dynamic, dynamic_max)

        stack_dynamic.pop()
    return dynamic_max


# 推荐ecs
def is_near_choose_ecs(region1, region2):
    region1_index = int(region1.split('-')[2])
    region2_index = int(region2.split('-')[2])
    if region1_index == region2_index or region2_index == region1_index - 1 or region2_index == region1_index + 1 or region2_index == region1_index - 6 or region2_index == region1_index + 6:
        return True
    else:
        return False


# msv的周期性分析
def msv_periodicity(test_tuple):
    periodicity_count = []
    for i in range(len(test_tuple)):
        periodicity_count.append(0)

    for i in range(len(test_tuple)):
        leaf_half = int((len(test_tuple) - i) / 2)
        for j in range(2, leaf_half + 1):
            is_break = False
            if test_tuple[i: i + j] == test_tuple[i + j: i + 2*j]:
                is_continue = True
                periodicity_temp = 2
                start_index = i + 2 * j
                end_index = i + 2 * j
                while is_continue:
                    if test_tuple[start_index: start_index+j] == test_tuple[i: i + j]:
                        periodicity_temp += 1
                        is_continue = True
                        start_index += j
                        end_index = start_index
                    else:
                        is_break =True
                        is_continue = False

                for k in range(i, end_index):
                    if periodicity_count[k] < periodicity_temp:
                        periodicity_count[k] = periodicity_temp
            if is_break:
                break
    return periodicity_count


# def change_file(file):
#     if file['categories'] == '' and file['subtype'] == '':
#         return  file
#     else:
#         if file['categories'] ==


# # list 转 csv
# def to_csv():
#     data = [dict(zip([col[0] for col in desc], row)) for row in alldata]
#     name = ['uuid', 'webshell', 'DDOS木马', '被污染的基础软件', '恶意程序', '恶意脚本文件', '感染型病毒', '黑客工具', '后门程序', '勒索病毒', '漏洞利用程序', '木马程序', '蠕虫病毒', '挖矿程序', '自变异木马']
#     test = pd.DataFrame(columns=name, data=data)
#     print(test)
#     test.to_csv('./data_malware_type.csv')


# 读取csv
#     df = pd.read_csv(str(BASE_DIR) + '//backend//data//malware_cluster.csv', usecols=[1, 21])
#     data_color = df.iloc[:, 0:2].values
#     data_color_dict = {}
#     for i in range(len(data_color)):
#         data_color_dict[data_color[i][0]] = data_color[i][1]


# 转json
#     datas = {'datas': data}
#     jsonData = json.dumps(datas)
#     print(jsonData)
#     fileObject = open('data_6h.json', 'w')
#     fileObject.write(jsonData)
#     fileObject.close()

# 读json
# with open(str(BASE_DIR) + '//backend//data//malware_cluster.csv','r',encoding='utf8')as fp:
#     json_data = json.load(fp)


# "select * from XX where id in ({}).format('1,2,3')"  参数化
