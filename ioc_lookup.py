import requests
import csv
import re
import datetime

API_KEY = 'api key'
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

#UNIX timestamp to regular old boring date
def normal_date(date):
    return datetime.datetime.fromtimestamp(date).strftime('%Y-%m-%d')

#hash result
def hash_result(iocs_hash, ioc_list):
    fieldnames = ['ioc', 'malicious_status', 'vendor_flagged', 'type_description', 'md5', 'sha1', 'sha256', 'times_submitted', 'popular_threat_classification', 'first_submission_date']

    with open('iocs_hash.csv', mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
        for ioc in iocs_hash:
            ioc_info = ioc_list[0]
            ioc_info['ioc'] = ioc
            reputation = get_reputation(ioc) #lookup in VT

            if 'last_analysis_stats' in reputation:
                ioc_info['malicious_status'] = 'malicious' if int(reputation['last_analysis_stats']['malicious']) > 0 else 'non-malicious'
                ioc_info['vendor_flagged'] = reputation['last_analysis_stats']['malicious']

            ioc_info['type_description'] = reputation['type_description']
            ioc_info['md5'] = reputation['md5']
            ioc_info['sha1'] = reputation['sha1']
            ioc_info['sha256'] = reputation['sha256']
            ioc_info['times_submitted'] = reputation['times_submitted']
            ioc_info['popular_threat_classification'] = reputation['popular_threat_classification']['suggested_threat_label']
            ioc_info['first_submission_date'] = normal_date(reputation['first_submission_date'])

            writer.writerow(ioc_info)


#url result
def url_result(iocs_url, ioc_list):
    fieldnames = ['ioc', 'malicious_status', 'vendor_flagged', 'threat_names', 'categories', 'last_modification_date', 'times_submitted', 'first_submission_date', 'last_final_url','last_http_response_code','title']

    with open('iocs_url.csv', mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
        for ioc in iocs_url:
            ioc_info = ioc_list[1]
            ioc_info['ioc'] = ioc
            reputation = get_reputation(ioc) #lookup in VT

            if 'last_analysis_stats' in reputation:
                ioc_info['malicious_status'] = 'malicious' if int(reputation['last_analysis_stats']['malicious']) > 0 else 'non-malicious'
                ioc_info['vendor_flagged'] = reputation['last_analysis_stats']['malicious']

            ioc_info['threat_names'] = reputation['threat_names'][0] if len(reputation['threat_names'])> 0 else 'none'
            ioc_info['categories'] = reputation['categories']['Forcepoint ThreatSeeker'] if reputation['categories']['Forcepoint ThreatSeeker'] else ''
            ioc_info['last_modification_date'] = normal_date(reputation['last_modification_date'])
            ioc_info['times_submitted'] = reputation['times_submitted']
            ioc_info['first_submission_date'] = normal_date(reputation['first_submission_date'])
            ioc_info['last_final_url'] = reputation['last_final_url']
            ioc_info['last_http_response_code'] = reputation['last_http_response_code']
            ioc_info['title'] = reputation['title']

            writer.writerow(ioc_info)

#domain result
def domain_result(iocs_domain, ioc_list):
    fieldnames = ['ioc', 'malicious_status', 'vendor_flagged', 'categories', 'tld', 'IP_address', 'last_dns_records_date', 'last_analysis_date', 'last_https_certificate_date', 'last_modification_date']

    with open('iocs_domain.csv', mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
        for ioc in iocs_domain:
            ioc_info = ioc_list[2]
            ioc_info['ioc'] = ioc
            ip = ''
            reputation = get_reputation(ioc) #lookup in VT

            if 'last_analysis_stats' in reputation:
                ioc_info['malicious_status'] = 'malicious' if int(reputation['last_analysis_stats']['malicious']) > 0 else 'non-malicious'
                ioc_info['vendor_flagged'] = reputation['last_analysis_stats']['malicious']

            if reputation['last_dns_records']:
                for record in reputation['last_dns_records']:
                    if record['type'] == 'A':
                        ip = ip + record['value'] + '\n'
            
            ioc_info['categories'] = reputation['categories']['Forcepoint ThreatSeeker'] if reputation['categories']['Forcepoint ThreatSeeker'] else ''
            ioc_info['tld'] = reputation['tld']
            ioc_info['IP_address'] = ip
            ioc_info['last_dns_records_date'] = normal_date(reputation['last_dns_records_date'])
            ioc_info['last_analysis_date'] = normal_date(reputation['last_analysis_date'])
            ioc_info['last_https_certificate_date'] = normal_date(reputation['last_https_certificate_date'])
            ioc_info['last_modification_date'] = normal_date(reputation['last_modification_date'])

            writer.writerow(ioc_info)

#IP result
def ip_result(iocs_ip, ioc_list):
    fieldnames = ['ioc', 'malicious_status', 'vendor_flagged', 'regional_internet_registry', 'network', 'country', 'continent', 'asn', 'as_owner', 'last_modification_date']

    with open('iocs_ip.csv', mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    
        for ioc in iocs_ip:
            ioc_info = ioc_list[3]
            ioc_info['ioc'] = ioc
            reputation = get_reputation(ioc) #lookup in VT

            if 'last_analysis_stats' in reputation:
                ioc_info['malicious_status'] = 'malicious' if int(reputation['last_analysis_stats']['malicious']) > 0 else 'non-malicious'
                ioc_info['vendor_flagged'] = reputation['last_analysis_stats']['malicious']
            
            ioc_info['regional_internet_registry'] = reputation['regional_internet_registry']
            ioc_info['network'] = reputation['network']
            ioc_info['country'] = reputation['country']
            ioc_info['continent'] = reputation['continent']
            ioc_info['asn'] = reputation['asn']
            ioc_info['as_owner'] = reputation['as_owner']
            ioc_info['last_modification_date'] = normal_date(reputation['last_modification_date'])

            writer.writerow(ioc_info)


def main():
    ioc_file = 'ioc_list.txt'
    iocs_hash, iocs_url, iocs_domain, iocs_ip = [], [], [], []
    ioc_list = [
        {'ioc':'', 'malicious_status':'', 'vendor_flagged':'', 'type_description':'', 'md5':'', 'sha1':'', 'sha256':'', 'times_submitted':'', 'popular_threat_classification':'', 'first_submission_date':''}, #hash
        {'ioc':'', 'malicious_status':'', 'vendor_flagged':'', 'threat_names':'', 'categories':'', 'last_modification_date':'', 'times_submitted':'', 'first_submission_date':'', 'last_final_url':'', 'last_http_response_code':'', 'title':''}, #url
        {'ioc':'', 'malicious_status':'', 'vendor_flagged':'', 'categories':'', 'tld':'', 'IP_address':'', 'last_dns_records_date':'', 'last_analysis_date':'', 'last_https_certificate_date':'', 'last_modification_date':''}, #domain
        {'ioc':'', 'malicious_status':'', 'vendor_flagged':'', 'regional_internet_registry':'', 'network':'', 'country':'', 'continent':'', 'asn':'', 'as_owner':'', 'last_modification_date':''}  #IP
    ]


    with open(ioc_file, mode='r') as f:
        for line in f:
            
            #remove comma, whitespace and refang
            line = line.strip().translate({ ord(i): None for i in '[],'})

            #hash
            if re.match(r'^[a-fA-F0-9]{32}$', line) or re.match(r'^[a-fA-F0-9]{40}$', line) or re.match(r'^[a-fA-F0-9]{64}$', line):
                iocs_hash.append(line) 
            #url    
            if re.match(r'^https?:\/\/', line):
                iocs_url.append(line) 
            #domain I guess    
            if re.match(r'(^\w+)(\.\w+$)', line):
                iocs_domain.append(line) 
            #IP address v4 only    
            if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line):
                iocs_ip.append(line.strip().translate({ ord(i): None for i in '[],'}))

    if iocs_hash:
        hash_result(iocs_hash, ioc_list) #get hash lookup result
    if iocs_url:
        url_result(iocs_url, ioc_list) #get url lookup result
    if iocs_domain:
        domain_result(iocs_domain, ioc_list) #get url lookup result
    if iocs_ip:
        ip_result(iocs_ip, ioc_list) #get url lookup result

    

                

if __name__ == '__main__':
    main()
