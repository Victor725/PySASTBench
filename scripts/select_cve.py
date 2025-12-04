import pandas as pd

df = pd.read_csv("/home/nkamg/SASTcomparison/CVE-Collection-2025-1-5.csv")
#print(df.head())
df = df[df["vul position"] != '*']

#print(df["CVE"])
#df['CVE'][0]='1'
#df.loc[0, 'CVE']='test'
#print(df['CVE'])

CVE_LIST = []
for i in range(len(df['CVE'])):
    #print(i)
    raw_data:str = df.iloc[i, 0]
    #print(raw_data)
    if type(raw_data) == str:
        cve_pos = raw_data.find('CVE-')
        cve_num = raw_data[cve_pos:]
        CVE_LIST.append(cve_num)
    
print(CVE_LIST)
with open("/home/nkamg/SASTcomparison/CVE_GT.txt", 'w') as f:
    f.write("\n".join(CVE_LIST))