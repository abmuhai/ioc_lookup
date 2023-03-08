import requests
import csv
import re

API_KEY = 'api'
VT_URL = 'https://www.virustotal.com/api/v3/'

#just some random comments
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

#lookup
def get_reputation(ioc):
    response = search_ioc(ioc)

    if response:
        data = response['data']
        if data:
            return data[0]['attributes']
    return None

def put_value(ioc, reputation):
    ioc_info = {'ioc': ioc, 'malicious_status':'', 'vendor_flagged':'', 'type_description':'', 'md5':'', 'sha1':'', 'sha256':'', 'times_submitted':'', 'popular_threat_classification':'', 'first_submission_date':''}
    
    if reputation:
        if 'last_analysis_stats' in reputation:
            ioc_info['malicious_status'] = 'malicious' if int(reputation['last_analysis_stats']['malicious']) > 0 else 'non-malicious'
            ioc_info['vendor_flagged'] = reputation['last_analysis_stats']['malicious']

        #only hashes have these
        if  re.match(r'^[a-fA-F0-9]{32,}$', ioc):
            ioc_info['type_description'] = reputation['type_description']
            ioc_info['md5'] = reputation['md5']
            ioc_info['sha1'] = reputation['sha1']
            ioc_info['sha256'] = reputation['sha256']
            ioc_info['times_submitted'] = reputation['times_submitted']
            ioc_info['popular_threat_classification'] = reputation['popular_threat_classification']['suggested_threat_label']
            ioc_info['first_submission_date'] = reputation['first_submission_date']
             
    return ioc_info

def main():
    ioc_file = 'ioc_list.txt'
    iocs = []

    with open(ioc_file, mode='r') as f:
        for line in f:
            iocs.append(line.strip().translate({ ord(i): None for i in '[],'})) #remove space and refang

    with open('iocs.csv', mode='w', newline='') as csvfile:
        fieldnames = ['ioc', 'malicious_status', 'vendor_flagged', 'type_description', 'md5', 'sha1', 'sha256', 'times_submitted', 'popular_threat_classification', 'first_submission_date']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc in iocs:

            reputation = get_reputation(ioc) #lookup in VT
            ioc_info = put_value(ioc, reputation) #get the lookup result

            writer.writerow(ioc_info)

                

if __name__ == '__main__':
    main()
