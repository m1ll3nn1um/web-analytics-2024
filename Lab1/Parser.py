from apachelogs import LogParser
from user_agents import parse as PA
import pandas
import matplotlib.pyplot as plt
from iptocc import get_country_code


def Get_country(ip):
    try:
        response = get_country_code(ip)
        return response
    except Exception:
        return None


def Parse_line(line):
    try:
        parser = LogParser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
        entry = parser.parse(line)
    
        D = {
        "IP": entry.remote_host,
        "Country": Get_country(entry.remote_host),
        "Date": str(entry.request_time.date()),
        "Time": str(entry.request_time.time()),
        "Size": int(entry.bytes_sent),
        "Request url": entry.headers_in["Referer"],
        "User_agents": entry.headers_in["User-Agent"],
        "Browser": PA(entry.headers_in["User-Agent"]).browser,
        "OS": PA(entry.headers_in["User-Agent"]).os.family
        }   
    except Exception:
        return None
    
    return D 


def Get_data(path):
    c = 0
    data=[]
    with open(path, 'r') as file:
        lines = file.readlines()
        for line in lines:
            tmp=Parse_line(line)
            if tmp is not None:
                c += 1
                data.append(tmp)
        df = pandas.DataFrame(data)
        print('==>', c)
        return df
    

def Calc_unic_users(data):
    print("Users by days:")
    result = data.groupby('Date')['IP'].nunique().sort_values(ascending=False)
    print(result)

def Calc_unic_os(data):
    print("Users by OS:")
    result = data.groupby('OS')['IP'].nunique().sort_values(ascending=False)
    print(result)

def Calc_unic_browser(data):
    print("Unique browsers:")
    result = data.groupby('Browser')['IP'].nunique().sort_values(ascending=False)
    print(result)

def Calc_unic_contry(data):
    print("Countries:")
    result = data.groupby('Country')['IP'].nunique().sort_values(ascending=False)
    print(result)


def Show_unique_bots(data):
    bots = ['Googlebot', 'Bingbot', 'Yahoo! Slurp', 'DuckDuckBot', 'Baiduspider']
    data['Bot'] = data['User_agents'].apply(lambda x: next(
        (bot for bot in bots if bot in x), None))
    unique_bots = data.groupby('Bot')['IP'].nunique()
    print(unique_bots)

def Calculate_z_score(x, mean_val, std_dev):
    return (x - mean_val) / std_dev


def Detect_anomalies(data):

    mean_val = data['Size'].mean()
    std_dev = data['Size'].std()
    data['Size_Z_Score'] = data['Size'].apply(lambda x: Calculate_z_score(x, mean_val, std_dev))
    print(data['Size_Z_Score'])
    df_zscore = data['Size_Z_Score']

    anomalies = data[data['Size_Z_Score'] > 3]
    print(f"Found {len(anomalies)} anomalies")

    # Plot anomalies
    plt.figure(figsize=(10, 5))
    plt.plot(data.index, data['Size'], label='Size', color="blue", alpha=0.25)
    plt.scatter(anomalies.index, anomalies['Size'], color="green", label= "Anomalies", marker="*")
    plt.title(f"Anomalies")
    plt.ylabel('Size')
    plt.grid(True)
    plt.tight_layout()
    plt.legend()
    plt.show()


data=Get_data("./access.log")

Calc_unic_users(data)
Calc_unic_os(data)
Calc_unic_browser(data)
Calc_unic_contry(data)
Show_unique_bots(data)

Detect_anomalies(data)
