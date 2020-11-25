from backend.config import INIT_TIME, FINAL_TIME
import datetime

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
def get_file_and_time_where_str(malware_type_list, malware_subtype_list, malware_filetype_list, begin_time_str, end_time_str):
    where_str = ''
    malware_type_str = '\',\''.join(malware_type_list)
    malware_subtype_str = '\',\''.join(malware_subtype_list)
    malware_filetype_str = '\',\''.join(malware_filetype_list)

    where_str = 'where first_time > \'' + begin_time_str + '\' and first_time < \'' + end_time_str + '\' '

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
    where_str = 'where first_time > \'' + begin_time_str + '\' and first_time < \'' + end_time_str + '\' '
    return where_str

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