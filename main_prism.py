# import functions
from nutanix_functions import *

# check if argument was passed to the script
if len(sys.argv) == 1:
   print('ERROR: you should pass a json config file as argument to the script')
   exit(1)

# load config and variables
file_config = sys.argv[1]
json_config = json.load(open(file_config))
cluster_api = json_config['cluster']['virtual_ip']
cluster_user = json_config['user']
cluster_pwd = json_config['pwd']
cluster_eula = json_config['eulas']
cluster_pulse = json_config['pulse']
cluster_dsip = json_config['cluster']['data_service_ip']
cluster_networks = json_config['networks']
cluster_images = json_config['images']
cluster_dns = json_config['cluster']['dns']
cluster_ntp = json_config['cluster']['ntp']
cluster_directories = json_config['directory']
cluster_pc_metadata_file = json_config['pc']['metadata_file']
cluster_pc_binary_file = json_config['pc']['binary_file']
cluster_pc_ip = json_config['pc']['virtual_ip']
pc_details = json_config['pc']
pc_name = pc_details['name']
pc_ip = pc_details['virtual_ip']
pc_dns = cluster_dns
pc_network_mask =  pc_details['network_mask']
pc_network_gateway = pc_details['network_gateway']

# main

# region eulas
print("\n--- Eulas section ---")
prism_eula_details = prism_get_eula(cluster_api,cluster_user,cluster_pwd)
if 'userDetailsList' not in prism_eula_details['entities'][0]:
    prism_accept_eula(cluster_api,cluster_user,cluster_pwd,cluster_eula['username'],cluster_eula['company'],cluster_eula['jobtitle'])
else:
    print("Eulas aready accepted on Nutanix cluster {}".format(cluster_api))
# endregion

# region pulse
print("\n--- Pulse section ---")
prism_pulse_status = prism_get_pulse(cluster_api,cluster_user,cluster_pwd)
if prism_pulse_status['isPulsePromptNeeded'] != False or prism_pulse_status['enable'] != cluster_pulse:
    prism_enable_pulse(cluster_api,cluster_user,cluster_pwd,cluster_pulse)
else:
    print("Pulse already configured on Nutanix cluster {}".format(cluster_api))
# endregion

# # region data service ip
print("\n--- Data service ip section ---")
cluster_details = prism_get_cluster(cluster_api,cluster_user,cluster_pwd)
if cluster_details['clusterExternalDataServicesIPAddress'] != cluster_dsip:
    prism_set_dsip(cluster_api,cluster_user,cluster_pwd,cluster_dsip)
else:
    print("Cluster Data Service IP {} already configured on Nutanix cluster".format(cluster_dsip,cluster_api))
# # endregion

# region networks
print("\n--- Network section ---")
for network in cluster_networks:
    prism_network_details = prism_get_networks(cluster_api,cluster_user,cluster_pwd,network_name=network['name'])
    if prism_network_details == None:
        if 'ipam' in network:
            prism_create_network(cluster_api,cluster_user,cluster_pwd,network['name'],network['vlan'],network['ipam']['address'],network['ipam']['gateway'],network['ipam']['prefix'],network['ipam']['pool'])
        else:
            prism_create_network(cluster_api,cluster_user,cluster_pwd,network['name'],network['vlan'])
    else:
        print("Network {} already created on Nutanix cluster {}".format(network['name'],cluster_api))
#endregion

# region upload images (qcow2)
print("\n--- Images section ---")
for image in cluster_images:
    prism_image_details = prism_get_images(cluster_api,cluster_user,cluster_pwd,image_name=image['name'])
    if prism_image_details == None:
        prism_container_uuid = prism_get_container_uuid(cluster_api,cluster_user,cluster_pwd,image['container'])
        image_task = prism_upload_image_url(cluster_api,cluster_user,cluster_pwd,image['name'],image['description'],image['url'],prism_container_uuid)
        image_task_uuid = image_task['taskUuid']
        prism_monitor_task_v2(cluster_api,cluster_user,cluster_pwd,image_task_uuid,retry_delay_secs=10,max_attemps=30)
    else:
        print("Image {} already uploaded on Nutanix cluster {}".format(image['name'],cluster_api))
# endregion

# region dns
print("\n--- DNS section ---")
dns_details = prism_get_dns(cluster_api,cluster_user,cluster_pwd)
for dns_server in cluster_dns:
    if dns_server not in dns_details:
        prism_add_dns(cluster_api,cluster_user,cluster_pwd,dns_server)
    else:
        print("DNS {} already configured on Nutanix cluster {}".format(dns_server,cluster_api))
# endregion

# region ntp
print("\n--- NTP section ---")
ntp_details = prism_get_ntp(cluster_api,cluster_user,cluster_pwd)
for ntp_server in cluster_ntp:
    if ntp_server not in ntp_details:
        prism_add_ntp(cluster_api,cluster_user,cluster_pwd,ntp_server)
    else:
        print("NTP {} already configured on Nutanix cluster {}".format(ntp_server,cluster_api))
# endregion


# region AD
print("\n--- Active Directory section ---")
for directory in cluster_directories:
    directory_details = prism_get_directory(cluster_api,cluster_user,cluster_pwd,directory['domain'])
    if directory_details == None:
        prism_set_directory(cluster_api,cluster_user,cluster_pwd,directory['name'],directory['domain'],directory['url'],directory['svc_user'],directory['svc_pwd'])
    else:
        print("Directory {} already configured on Nutanix cluster {}".format(directory['domain'],cluster_api))

#endregion

# region role mapping
print("\n--- Role Mapping section ---")
for directory in cluster_directories:
    directory_details = prism_get_directory(cluster_api,cluster_user,cluster_pwd,directory['domain'])
    if directory_details:
        role_mappings_details = prism_get_role_mappings(cluster_api,cluster_user,cluster_pwd,directory['name'])
        if not role_mappings_details:
            for role in directory['role_mapping']:
                prism_set_role_mapping(cluster_api,cluster_user,cluster_pwd,directory['name'],role['name'],role['type'],role['value'])
        else:
            for role in directory['role_mapping']:
                role_exist = False
                for role_detail in role_mappings_details:
                    if role['name'] in role_detail['role']:
                        role_exist = True # role exist
                if role_exist == False:
                    prism_set_role_mapping(cluster_api,cluster_user,cluster_pwd,directory['name'],role['name'],role['type'],role['value'])
                else:
                    print("Role {} already configured on Nutanix cluster {}".format(role['name'],cluster_api))
    else:
        print("Directory {} not configured on Nutanix cluster {}".format(directory['domain'],cluster_api))
# endregion

#region PC software upload (works only on a dark site environment - upload binary method instead of downloading)
print("\n--- PC softwares upload section ---")
pc_softwares_details = prism_get_pc_software(cluster_api,cluster_user,cluster_pwd)
if not pc_softwares_details: # if empty, we upload provided PC binary
    print("PC softwares not available on Nutanix Cluster {}".format(cluster_api))
    prism_software_upload(cluster_api,cluster_user,cluster_pwd,cluster_pc_metadata_file,cluster_pc_binary_file)
else:
    print("PC software already available on Nutanix cluster {}".format(cluster_api))
# endregion

# region PC VM deploy
# region retreiving PC softwares details
print("\n--- PC deploy section ---")
pc_vm_details = prism_get_vms(cluster_api,cluster_user,cluster_pwd,vm_name=pc_name)
if not pc_vm_details:
    pc_softwares_details = prism_get_pc_software(cluster_api,cluster_user,cluster_pwd)
    if pc_softwares_details:
        cluster_details = prism_get_cluster(cluster_api,cluster_user,cluster_pwd)
        cluster_aos_version = cluster_details['version'] # get aos version
        for pc in pc_softwares_details:
            if pc['status'] == "COMPLETED" and cluster_aos_version in pc['compatiblePeNosVersions']:
                pc_version = pc['version']
                for pc_size in pc['prismCentralSizes']:
                    if pc_size['pcVmFormFactor'] == "small": # get cpu/mem/disk details
                        pc_form_factor_details = pc_size
                        break  # get the first one
        # endregion

        # region deploying PC VM         
        pc_cpu = pc_form_factor_details['vcpus']
        pc_mem = pc_form_factor_details['memorySizeInGib']
        pc_disk = pc_form_factor_details['diskSizeInGib']
        network_uuid = prism_get_network_uuid(cluster_api,cluster_user,cluster_pwd,network_name=pc_details['network_name']) 
        container_uuid =  prism_get_container_uuid(cluster_api,cluster_user,cluster_pwd,container_name=pc_details['container_name'])  
        
        # deploy and monitor progress
        pc_deploy_vm_task = prism_create_pc_vm(cluster_api,cluster_user,cluster_pwd,pc_version,pc_name,pc_ip,pc_cpu,pc_mem,pc_disk,pc_dns,pc_network_mask,pc_network_gateway,container_uuid,network_uuid)
        pc_deploy_vm_task_uuid = pc_deploy_vm_task['task_uuid']
        prism_monitor_task_v2(cluster_api,cluster_user,cluster_pwd,pc_deploy_vm_task_uuid,retry_delay_secs=60,max_attemps=60)
        # endregion
    else:
        print("PC softwares not available on Nutanix Cluster {} - Skipping PC VM deployment".format(cluster_api))
elif pc_vm_details and pc_vm_details[0]['vmType'] == 'kPCVM':
        print("PC VM {} already deployed on Nutanix cluster {}".format(pc_name,cluster_api))
# endregion

# region PC registration
print("\n--- PC registration section ---")
pc_vm_details = prism_get_vms(cluster_api,cluster_user,cluster_pwd,vm_name=pc_name)
cluster_details = prism_get_cluster(cluster_api,cluster_user,cluster_pwd)
if cluster_details['isRegisteredToPC'] == None and pc_vm_details: # if PE not registered and PC vm exist
    prism_register_pc(cluster_api,cluster_user,cluster_pwd,cluster_pc_ip,pc_username="admin",pc_secret="nutanix/4u")
else:
    print("Nutanix Cluster {} already registered on Prism Central instance {}".format(cluster_api,cluster_pc_ip))
# endregion