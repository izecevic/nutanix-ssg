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
        cluster_virtual_ip, cluster_name, redundancy_factor, dns, ntp, timezone. For each node,
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
            'image_now': True
        })
    # endregion
    
    # region populate foundation cluster details
    print("Populating foundation cluster details..")
    foundation_payload['clusters'] = [{
        'cluster_external_ip': foundation_config['virtual_ip'],
        'cluster_name' : foundation_config['name'],
        'redundancy_factor' : int(foundation_config['replication_factor']),
        'cluster_members' : [cvm['cvm_ip'] for cvm in foundation_config['nodes']],
        'cvm_dns_servers': foundation_config['dns'],
        'cvm_ntp_servers': foundation_config['ntp'],
        'timezone': foundation_config['timezone'],
        'cluster_init_now' : True
    }]
    # endregion

    return foundation_payload
# endregion

# region foundation_image_nodes
def foundation_image_nodes (api_server,foundation_payload,username=None,secret=None):
    """
        Trigger a foundation imaging process

    Args:
        api_server: The Foundation API server
        foundation_payload: json payload used by Foundation to image a given set of nodes 
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
        Retreive status of current foundation imaging progress

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
        Monitor current foundation imaging progress with a maximum attemps and retry configurable. 

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        max_attemps: default 120
        retry_delay_secs: default 60 seconds
        
    Returns:
        Success or Failure
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

# region prism_update_default_pwd
def prism_update_default_pwd(api_server,new_secret,username='admin',default_secret='nutanix/4u'):
    """
        Change Prism default admin password with new provided password

    Args:
        api_server: The IP or FQDN of Prism/PC.
        username: The Prism/PC user name.
        new_secret : The Prism/PC user name password
        default_secret: default password upon foundation (nutanix/4u)
        
    Returns:
        None
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/utils/change_default_system_password"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'oldPassword': default_secret,
        'newPassword': new_secret    
    }
    # endregion

    # Making the call
    print("Updating default Prism admin password on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,default_secret,headers,payload)
# endregion

# region get pulse
def prism_get_pulse(api_server,username,secret):
    """
        Retrieve pulse details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Pulse details (part of the json response)
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/pulse"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    #endregion

    # make the call
    print("Getting Pulse details on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    return resp
# endregion

# region enable pulse
def prism_enable_pulse(api_server,username,secret,enable_pulse):
    """
        Enable Pulse on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        enable_pulse: True or False
        
    Returns:
         Eulas details (part of the json response)
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/pulse"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PUT"
    payload = {
        'enable':enable_pulse, 
        'enableDefaultNutanixEmail':False, 
        'isPulsePromptNeeded':False, 
        'remindLater':False
    }
    #endregion

    # make the call
    print("Configuring Pulse on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    return resp
# endregion

# region prism_get_eula
def prism_get_eula(api_server,username,secret):
    """
        Retrieve eulas details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Eulas details (part of the json response)
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/eulas"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    #endregion

    # make the call
    print("Getting Eula details on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    return resp
# endregion

# region prism_accept_eula
def prism_accept_eula(api_server,username,secret,eula_username,eula_companyname,eula_jobtitle):
    """
        Accept eulas on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        eula_username: Username for the eulas
        eula_companyname: Company Name for the eulas
        eula_jobtitle: Job Title for the Eulas
        
    Returns:
         True
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/eulas/accept"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'username': eula_username,
        'companyName': eula_companyname,
        'jobTitle': eula_jobtitle
    }
    #endregion

    # make the call
    print("Accepting Eulas on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    return resp
# endregion

# region prism_get_cluster
def prism_get_cluster(api_server,username,secret):
    """
        Retrieve Cluster details on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        
    Returns:
         Cluster details (part of the json response)
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    #endregion

    # make the call
    print("Getting cluster details on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)
    return resp
# endregion

# region configure data service ip
def prism_set_dsip(api_server,username,secret,cluster_dsip):
    """
        Configure a Data Service IP (DSIP) on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        cluster_dsip: Data service IP
        
    Returns:
         None
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/cluster/"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "PATCH"
    payload = {'clusterExternalDataServicesIPAddress': cluster_dsip}
    #endregion

    # make the call
    print("Configuring a Data Service IP on Nutanix cluster {}".format(api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    return resp
# endregion

# region prism_get_networks
def prism_get_networks(api_server,username,secret,network_name=None):
    """
       Retreive the list of networks from Prism Element.
       If a network_name is specified, only details for that given network will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        network_name (optional): Name of the network
        
    Returns:
         A list of networks (entities part of the json response).
    """

    # variables
    net_list = []

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/networks"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    # endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # processing the response
    if network_name == None:
        print("Returning all networks on Nutanix cluster {}".format(api_server))
        net_list.extend(resp['entities'])
        return net_list
    else: 
        for network in resp['entities']:
            if network['name'] == network_name:
                print("Returning network {} on Nutanix cluster {}".format(network_name,api_server))
                net_list.append(network)
                return net_list
# endregion

# region prism_create_network
def prism_create_network(api_server,username,secret,network_name,network_vlan,network_ipam_address=None,network_ipam_gateway=None,network_ipam_prefix=None,network_ipam_pool=None):
    """
       Create a network on Prism Element

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        network_name: Name of the network
        network_vlan: Vlan of the network
        network_ipam_address (optional): IPAM network address
        network_ipam_gateway (optional): IPAM network default gateway
        network_ipam_prefix (optional): IPAM network prefix
        network_ipam_pool (optional): IPAM network pool
        
    Returns:
         Network created
    """

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/networks"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'name': network_name, 
        'vlan_id': network_vlan
    } 

    # updating payload with ipam when relevant
    if network_ipam_address != None:
        payload.update(ip_config = {
            'default_gateway': network_ipam_gateway,
            'network_address': network_ipam_address,
            'prefix_length': network_ipam_prefix,
            'pool': [
                {'range': network_ipam_pool}
             ]
        })

    # endregion

    # # Making the call
    print("Creating network {} on Nutanix cluster {}".format(network_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    return resp
# endregion

# region get containers
def prism_get_containers(api_server,username,secret,container_name=None):
    """
        Retreive the list of containers from Prism Element.
        If a container_name is specified, only details for that given container will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        container_name (optional): Name of the container
        
    Returns:
         A list of containers (entities part of the json response).
    """
    # variables
    containers_list = []

    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/storage_containers"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET" 
    #endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # filtering
    if container_name == None:
        print("Returning all containers on Nutanix cluster {}".format(api_server))
        containers_list.extend(resp['entities'])
        return containers_list
    else: 
        for container in resp['entities']:
            if container['name'] == container_name:
                print("Returning container {} on Nutanix cluster {}".format(container_name,api_server))
                containers_list.append(container)
                return containers_list
# endregion

#region prism_get_container_uuid
def prism_get_container_uuid(api_server,username,secret,container_name):
    """
        Retreive container uuid

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        container_name Name of the container
        
    Returns:
         container uuid
    """
        
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v1/containers?filterCriteria=container_name=={}".format(container_name)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # return
    print ("Return container {} uuid".format(container_name))
    return resp['entities'][0]['containerUuid']
# endregion

# region prism_get_images
def prism_get_images(api_server,username,secret,image_name=None):
    """
       Retreive the list of images from Prism Element.
       If a image_name is specified, only details for that given network will be returned.

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        imamge_name (optional): Name of the image
        
    Returns:
         A list of images (entities part of the json response).
    """
    
    # variables
    images_list = []
    
    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    # endregion

    # Making the call
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers)

    # filtering
    if image_name == None:
        print("Returning all images on Nutanix cluster {}".format(api_server))
        images_list.extend(resp['entities'])
        return images_list
    else: 
        for image in resp['entities']:
            if image['name'] == image_name:
                print("Return single image {} on Nutanix cluster {}".format(image_name,api_server))
                images_list.append(image)
                return images_list
# endregion

# region prism_upload_image_url
def prism_upload_image_url(api_server,username,secret,image_name,image_description,image_url,container_uuid,image_type='DISK_IMAGE'):
    """
        Upload an image on Prism Element using the url method

    Args:
        api_server: The IP or FQDN of Prism.
        username: The Prism user name.
        secret: The Prism user name password.
        image_name: Image name.
        image_description: Image description.
        image_url: Image url.
        container_uuid: destination container uuid.
        image_type: DISK_IMAGE (default) or ISO.
        
    Returns:
         container uuid
    """

    # region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v0.8/images"
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "POST"
    payload = {
        'name': image_name,
        'annotation': image_description,
        'imageType': image_type,
        'imageImportSpec': {
            'containerUuid': container_uuid,
            'url': image_url
        }
    }
    # endregion

    # Making the call
    print("Uploading image {} on Nutanix cluster {}".format(image_name,api_server))
    print("Making a {} API call to {}".format(method, url))
    resp = process_request(url,method,username,secret,headers,payload)
    return resp
# endregion

# region prism_monitor_task_v2
def prism_monitor_task_v2(api_server,username,secret,task_uuid,retry_delay_secs=10,max_attemps=30):
    """
        Monitor a given task on Prism Element 

    Args:
        api_server: The Foundation API server
        username: None (no authentication on the foundation API)
        secret: None (no authentication on the foundation API)
        task_uuid: task uuid to monitor
        max_attemps: 30 (default)
        retry_delay_secs: 10 seconds (default)
        
    Returns:
        Success or Failure
    """
    
    # variables
    attempt = 1
    max_attempts = max_attemps # default is 30
    retry_delay_secs = retry_delay_secs # default is 10 seconds
    
    #region prepare the api call
    headers = {'Content-Type': 'application/json','Accept': 'application/json'}
    api_server_port = "9440"
    api_server_endpoint = "/api/nutanix/v2.0/tasks/{}".format(task_uuid)
    url = "https://{}:{}{}".format(api_server,api_server_port,api_server_endpoint)
    method = "GET"
    #endregion

    # track task process
    while attempt <= max_attempts:
        # make the api call
        print("Making a {} API call to {}".format(method, url))
        task_progress = process_request(url,method,username,secret,headers)
        print(json.dumps(task_progress, indent=4))
        print("Attempt number: {}".format(attempt))
        if task_progress['percentage_complete'] == 100 and task_progress['progress_status'] == "Succeeded":
            print("Task succeeded")
            return
        elif task_progress['progress_status'] == "Failed":
            print("Task failed")
            print(json.dumps(task_progress, indent=4))
            exit(1)
        else:
            print("WARNING: remaining attemps before failure: {0}".format(max_attempts-attempt))
            print("Let's wait for {} seconds..".format(retry_delay_secs))
            attempt +=1
            sleep(retry_delay_secs)
    print ("Error: Exceeded max attempts {}".format(max_attempts))
# endregion

# endregion