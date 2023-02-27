import requests
import csv

API_KEY = ''
VT_URL = 'https://www.virustotal.com/api/v3/'

def search_ioc(ioc):
    headers = {
        'x-apikey': API_KEY
    }
    params = {
        'include': 'analysis_results'
    }
    url = VT_URL + 'search?query=' + ioc
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_reputation(ioc):
    response = search_ioc(ioc)

    if response:
        data = response['data']
        if data:
            return data[0]['attributes']['last_analysis_stats']
    return None

def main():
    ioc_file = 'ioc_list.txt'
    iocs = []

    with open(ioc_file, mode='r') as f:
        for line in f:
            iocs.append(line.strip())

    with open('iocs.csv', mode='w', newline='') as csvfile:
        fieldnames = ['ioc', 'malicious status','vendor flagged']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:
            reputation = get_reputation(ioc)

            if reputation:
                malicious_status=''
                if int(reputation['malicious']) > 0:
                    malicious_status = 'malicious'
                else: 
                    malicius_status = 'no'

                writer.writerow({
                    'ioc': ioc,
                    'malicious status': malicious_status,
                    'vendor flagged': reputation['malicious']
                })

                

if __name__ == '__main__':
    main()
