import json, logging, requests, argparse, re

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

class DNScan():

    def __init__(self, service, domain):
        self.service = service
        self.domain = domain

        self.get_api_token()

    def get_api_token(self):
        with open ('config.json') as api:
            data = json.load(api)
            self.virustotal_api_token = data['virustotal']
            self.google_api_token = data['google_token']
            self.google_cse_token = data['google_cse']
            
    def google_scan(self):
        subdomains = set()
        start_index = 1
        while True:
            try:
                url = f'https://www.googleapis.com/customsearch/v1?q=site%3A{self.domain}&cx={self.google_cse_token}&key={self.google_api_token}&start={start_index}'
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    for item in items:
                        link = item.get('link', '')
                        domain = self.extract_google_domain(link)
                        if domain:
                            subdomains.add(domain)
                    start_index += 10
                    if len(items) < 10:
                        break
                else:
                    logging.error(f'Error while fetching Google Search query: {response.status_code}')
                    break
            except Exception as e:
                logging.error(f'Error while fetching GH query: {e}')
                break
        return subdomains
    
    def extract_google_domain(self, url):
        domain_regex = r'https?://(?:[^/]+?\.)*?([^/:]+)'
        match = re.match(domain_regex, url)
        if match:
            return match.group(1)
        else:
            return None


    def virustotal_scan(self):
        url = f'https://www.virustotal.com/api/v3/domains/{self.domain}'
        headers = {
            'accept': 'application/json',
            'x-apikey': self.virustotal_api_token
        }
        try:
            response = requests.get(url, headers=headers)

            json_response = response.json()
            subdomains = json_response['data']['attributes']['last_https_certificate']['extensions']['subject_alternative_name']
            for subdomain in subdomains:
                print(subdomain)
        except:
            pass

    def get_subdomain(self):
        if self.service == 'all':
            self.virustotal_scan()
            google_subdomains = self.google_scan()
            for subdomain in google_subdomains:
                print(subdomain)

        elif self.service == 'virustotal':
            self.virustotal_scan()

        elif self.service == 'google':
            google_subdomains = self.google_scan()
            for subdomain in google_subdomains:
                print(subdomain)
        else:
            logging.error('Service not avaible')
            pass
            
            
def main():
    parser = argparse.ArgumentParser(description='Scan subdomains of a domain using a specified service.')
    parser.add_argument('-d', '--domain',
                        help='The domain to use for scanning (e.g., "example.com")')
    parser.add_argument('--service', 
                        help='The service to use for scanning (e.g, "virustotal, google", default: all).', 
                        default='all')

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        return

    d = DNScan(args.service, args.domain)
    d.get_subdomain()


if __name__ == '__main__':
    main()
