import requests
import bs4
import logging
import gzip
import glob
import ipaddress
import json
import argparse
import logging
from elasticsearch import Elasticsearch

_base_url = "http://data.caida.org/datasets/routing/routeviews-prefix2as/"
def get_iptoasn_files(dir):
    dir = dir if "/" in dir else dir + '/'
    r = requests.get(_base_url)
    soup = bs4.BeautifulSoup(r.content, 'lxml')
    for a in soup.find_all('a', href=True):
        date = a['href']
        if date[0].isdecimal():
            year_dir = _base_url + date
            year_request = requests.get(year_dir)
            year_soup = bs4.BeautifulSoup(year_request.content, 'lxml')
            months = [month['href'] for month in year_soup.find_all('a', href=True) if month['href'][0].isdecimal()]
            month_dir = year_dir + months[0]
            month_request = requests.get(month_dir)
            month_soup = bs4.BeautifulSoup(month_request.content, 'lxml')
            iptoasn_files = [iptoasn_file['href'] for iptoasn_file in month_soup.find_all('a', href=True) if iptoasn_file['href'].startswith('routeviews')]
            file_to_grab = month_dir + iptoasn_files[0]
            r = requests.get(file_to_grab)
            logging.debug(f"Collecting {file_to_grab}...")
            with open(dir + iptoasn_files[0], 'wb') as iptoasn:
                iptoasn.write(r.content)

def convert_files(dir):
    #todo change the format to be a list of dictionaries for easier ES ingest
    asn_hosts_dates = dict()
    dir = dir if "/" in dir else dir + '/'
    for file in glob.glob(dir + '*'):
        logging.debug(f"Processing {file}...")
        asn_hosts = dict()
        date = file.split("-")[2]
        # filename = file.split("\\", 1)[1]
        with gzip.open(file, 'rb') as iptoasn:
            for line in iptoasn:
                line = line.decode("utf-8") 
                ip, cidr, asn = line.strip().split("\t")
                advertisment = ipaddress.IPv4Network(f"{ip}/{cidr}")
                if asn in asn_hosts:
                    asn_hosts[asn] += advertisment.num_addresses
                else:
                    asn_hosts[asn] = advertisment.num_addresses

        asn_hosts_dates[date] = asn_hosts
    return asn_hosts_dates

def dict_to_json_file(data, filename):
    with open(f"{filename}", "w") as outputFile:
        json.dump(data, outputFile)

def json_to_dict(filename):
    with open(f"{filename}", "r") as inputFile:
        return json.load(inputFile)

def es_connect(hostname):
    logging.debug("Connecting to Elastic...")
    res = requests.get(f"http://{hostname}")
    logging.debug(res.status_code)
    logging.debug(res.content)
    host, port = hostname.rsplit(":", 1)
    logging.debug(f"{host}, {port}")
    es = Elasticsearch()
    return es

def send_elements_to_es(es, data):
    full_list = []
    id_val = 0
    for date in data.keys():
        for key, val in data[date].items():
            node = {
                'File': date,
                'ASN': key,
                'Hosts': val
            }
            es.index(index="blaze3", id=id_val, body=node)
            id_val += 1
    return True

def batch_elements(data):
    full_list = []
    for date in data.keys():
        for key, val in data[date].items():
            node = {
                'File': date,
                'ASN': key,
                'Hosts': val
            }




if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    parser = argparse.ArgumentParser(prog="BlazeBois",
        usage='%(prog)s [options] path',
        description='Process some IPtoASN Files..'
    )
    parser.add_argument('-oF', '--outputFile', type=str, dest="outputFilename",
                        help='output file if storing processed results to file')
    parser.add_argument('-oE', '--outputElastic', type=str, dest="elastic",
                        help='Output to elastic, hostname with port i.e localhost:9200')

    parser.add_argument('-oD', '--outputDir', type=str, dest="dir",
                        help='output dir for the IP to ASN files')

    parser.add_argument('-lf', '--loadFile', type=str, dest="inputFilename",
                        help='Load already processed IPtoASN file if already pulled down')
    logging.debug("Starting BlazeBois...")
    args = parser.parse_args()
    print(args)
    if args.dir:
        dir = args.dir
    else:
        dir = "iptoasn"
    if args.inputFilename:
        data = json_to_dict(args.inputFilename)
    else:
        get_iptoasn_files(dir)
        data = convert_files(dir)
    if args.outputFilename:
        logging.debug("Outputing to file...")  
        dict_to_json_file(data, args.outputFilename) 
    elif args.elastic:
        logging.debug(f"Outputing to elastic at {args.elastic}...")
        es = es_connect(args.elastic)
        send_elements_to_es(es, data)
    else:
        logging.debug("Outputing Nowhere...")

