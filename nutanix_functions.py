import requests,json,urllib3,uuid,sys
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# region functions
# region function process_request
def process_request(url, method, user, password, headers, payload=None,secure=False, binary=False):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successfull.
    """
    if payload != None and binary == False:
       payload = json.dumps(payload)
    elif payload != None and binary == True:
        payload = payload

    #configuring web request behavior
    if binary == True: 
        timeout = 900 
    else:
        timeout = 30
    retries = 5
    sleep_between_retries = 5

    while retries > 0:
        try:
            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout,
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout,
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password),
                    verify=secure,
                    timeout=timeout
                )
        except requests.exceptions.HTTPError as error_code:
            print ("Http Error!")
            print("status code: {}".format(response.status_code))
            print("reason: {}".format(response.reason))
            print("text: {}".format(response.text))
            print("elapsed: {}".format(response.elapsed))
            print("headers: {}".format(response.headers))
            if payload is not None:
                print("payload: {}".format(payload))
            print(json.dumps(
                json.loads(response.content),
                indent=4
            ))
            exit(response.status_code)
        except requests.exceptions.ConnectionError as error_code:
            print ("Connection Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            else:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                sleep(sleep_between_retries)
                retries -= 1
                print ("retries left: {}".format(retries))
                continue
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            exit(1)
        except requests.exceptions.Timeout as error_code:
            print ("Timeout Error!")
            if retries == 1:
                print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
                exit(1)
            print('Error! Code: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            sleep(sleep_between_retries)
            retries -= 1
            print ("retries left: {}".format(retries))
            continue
        except requests.exceptions.RequestException as error_code:
            print ("Error!")
            exit(response.status_code)
        break

    if response.ok:
        print("Request suceedded!")
        return json.loads(response.content)
    if response.status_code == 401:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        exit(response.status_code)
    elif response.status_code == 500:
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        exit(response.status_code)
    else:
        print("Request failed!")
        print("status code: {0}".format(response.status_code))
        print("reason: {0}".format(response.reason))
        print("text: {0}".format(response.text))
        print("raise_for_status: {0}".format(response.raise_for_status()))
        print("elapsed: {0}".format(response.elapsed))
        print("headers: {0}".format(response.headers))
        if payload is not None:
            print("payload: {0}".format(payload))
        print(json.dumps(
            json.loads(response.content),
            indent=4
        ))
        exit(response.status_code)    
# endregion

# region foundation_get_aos
def foundation_get_aos (api_server,username=None,secret=None):
    """
       Retrieve a list of all AOS packages available on the foundation server

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
         A list of AOS packages
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/enumerate_nos_packages"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # make the api call
    print("Retrieving a list of AOS packages available on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    return resp
# endregion

# region foundation_get_hypervisors
def foundation_get_hypervisors (api_server,username=None,secret=None):
    """
       Retreive a list of all hypervisors packages available on the foundation server

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
         A list of AOS hypervisors
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/enumerate_hypervisor_isos"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # make the api call
    print("Retrieving a list of hypervisors available on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    return resp
# endregion

# region foundation_generate_image_payload
def foundation_generate_image_payload(foundation_config:dict):
    """
        Generates a json payload for foundation imaging endppoint to image a given set of nodes
        and create a Nutanix AHV cluster

    Args:
        foundation_config: json object with all keys required for node and cluster imaging
        The foundation_config json object should include the following keys (ipmi_netmask,
        hypervisor_netmask, cvm_netmask, ipmi_gateway, cvm_gateway, hypervisor_gateway, nos_package,
        cluster_virtual_ip, cluster_name, redudancy_factor, dns, ntp, timezone. For each node,
        the object should include node_position, hypervisor_hostame, hypervisor_ip, cvm_ip, ipmi_ip,
        ipmi_user and ipmi_pwd)
        
    Returns:
         A json payload used by Foundation to image a given set of nodes and create a Nutanix AHV cluster
    """

    # variables
    foundation_payload = {} # foundation payload
    
    # region populate foundation core details
    print("Populating foundation core details..")
    foundation_payload = {
        'clusters': [],
        'blocks': [{'block_id': None,'nodes': [],}],
        #'ipmi_vlan_mode': 'trunk',
        # 'ui_platform': foundation_config['ui_platform'],
        'ipmi_netmask': foundation_config['ipmi_netmask'], 
        'ipmi_gateway': foundation_config['ipmi_gateway'], 
        'cvm_netmask': foundation_config['hyp_cvm_netmask'],
        'cvm_gateway': foundation_config['hyp_cvm_gateway'], 
        'hypervisor_netmask': foundation_config['hyp_cvm_netmask'], 
        'hypervisor_gateway': foundation_config['hyp_cvm_gateway'],  
        'nos_package': foundation_config['nos_package'],
        'hypervisor': 'kvm', 
        'hypervisor_iso': {},
        'skip_network_setup': True,
        'is_imaging': True, 
        'is_installing_hypervisor': True, 
        'is_installing_cvm': True 
    }
    # endregion

    # region populate foundation nodes details
    print("Populating foundation nodes details..")
    for node in foundation_config['nodes']:
        # populate each node details
         foundation_payload['blocks'][0]['nodes'].append({ 
            'ipmi_user': node['ipmi_user'],
            'ipmi_password': node['ipmi_pwd'],
            'node_position': node['node_position'],
            'hypervisor_hostname': node['hypervisor_hostname'],
            'hypervisor_ip':node['hypervisor_ip'],
            'cvm_ip': node['cvm_ip'],
            'ipmi_ip': node['ipmi_ip'],
            #'cvm_gb_ram': 32, 
            #'ipmi_configure_now': True, 
            'image_now': True
        })
    # endregion
    
    # region populate foundation cluster details
    print("Populating foundation cluster details..")
    foundation_payload['clusters'] = [{
        'cluster_external_ip': foundation_config['virtual_ip'],
        'cluster_name' : foundation_config['name'],
        'redundancy_factor' : int(foundation_config['replication_factor']),
        #'cluster_members' : [cvm['cvm_ip'] for cvm in foundation_payload['blocks'][0]['nodes']],
        'cluster_members' : [cvm['cvm_ip'] for cvm in foundation_config['nodes']],
        'cvm_dns_servers': foundation_config['dns'],
        'cvm_ntp_servers': foundation_config['ntp'],
        'timezone': foundation_config['timezone'],
        #'cluster_init_successful' : True,
        'cluster_init_now' : True
    }]

    return foundation_payload
    # endregion
# endregion

# region foundation_image_nodes
def foundation_image_nodes (api_server,foundation_payload,username=None,secret=None):
    """
       Trigger a foundation imaging

    Args:
        api_server: The Foundation API server
        foundation_payload: son payload used by Foundation to image a given set of nodes 
        and create a Nutanix AHV cluster
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
        A foundation session-id
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/image_nodes"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = foundation_payload
    # endregion

    # make the api call
    print("Triggering a foundation imaging process on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    return resp
 # endregion

# region foundation_get_imaging_progress
def foundation_get_imaging_progress (api_server,username=None,secret=None):
    """
       Retreive current status of foundation imaging progress

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        
    Returns:
         json response with current foundation imaging progress details
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "8000"
    api_server_endpoint = "/foundation/progress"
    url = "http://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # make the api call
    print("Retrieving current imaging progress details on the foundation server {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    return resp
# endregion

# region foundation_monitor_progress
def foundation_monitor_progress (api_server,username=None,secret=None,max_attemps=120,retry_delay_secs=60):
    """
       Monitor current foundation imaging progress

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        max_attemps: default 120
        retry_delay_secs: default 60 seconds
        
    Returns:
        None
    """

    # variables
    attempt = 1
    max_attempts = max_attemps # default 2 hours
    retry_delay_secs = retry_delay_secs #default 60 seconds

    # track foundation imaging process
    while attempt <= max_attempts:
        # calling the function
        foundation_progress = foundation_get_imaging_progress(api_server)
        # track progress
        print("Foundation Time Spent: {} mins".format(attempt))
        print("Foundation Percentage Complete: {}%".format(foundation_progress['aggregate_percent_complete']))
        print("Cluster Name: {0}, Status: {1}, Percentage Complete {2}%".format(foundation_progress['clusters'][0]['cluster_name'],foundation_progress['clusters'][0]['status'],foundation_progress['clusters'][0]['percent_complete']))
        for node in foundation_progress['nodes']:
            print("Hypervivor IP: {0}, CVM IP: {1}, Installation: {2}%, Status: {3}".format(node['hypervisor_ip'], node['cvm_ip'], node['percent_complete'],node['status']))
        if foundation_progress['aggregate_percent_complete'] == 100:
            print("foundation succeeded")
            return
        elif foundation_progress['imaging_stopped'] == True or foundation_progress['abort_session'] == True:
            print("Error: during foundation, image stopped")
            exit(1)
        else:
            print("WARNING: remaining minutes before failure: {0} mins".format(max_attempts-attempt))
            print("let's wait for {} seconds..".format(retry_delay_secs))
            attempt +=1
            sleep(retry_delay_secs)
            
    print ("Error: Exceeded max attempts {}".format(max_attempts))
# endregion
# endregion