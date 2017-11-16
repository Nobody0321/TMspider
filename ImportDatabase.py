import  pymysql 

FileNames = ['DomainNames.txt','HostNames.txt','SampleNames.txt','EmailNames.txt']
tables = ['Domains','Hosts','Samples','Emails']

conn  = pymysql.connect(host = '127.0.0.1',user = 'root',passwd = '1234',charset = 'utf8')
cur = conn.cursor()

def store(database,table,title,List):
    for each  in List:
        sql = "insert into %s (%s) VALUE ('%s') " %(table ,title,each)
        print(sql)
        cur.execute(sql)
        print('1')

def getlist(filename):
    file =  open(filename,'r')
    namelist = file.read().split('\n')
    return namelist[:-1]

List = getlist('SampleNames.txt')
cur.execute('USE Threat_Miner')
store('Threat_Miner','Samples','sample_name',List)

conn.commit()
cur.execute('select * from Domains')
print(cur.fetchone())
print('2')
cur.close()
conn.close()