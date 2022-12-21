# import functions
from nutanix_functions import *

# check if argument was passed to the script
if len(sys.argv) == 1:
   print('ERROR: you should pass a json config file as argument to the script')
   exit(1)

# load config and variables
file_config = sys.argv[1]
json_config = json.load(open(file_config))
foundation_api = json_config['foundation_ip']
foundation_aos = json_config['cluster']['nos_package']
foundation_config = json_config['cluster']
cluster_api = json_config['cluster']['virtual_ip']
cluster_user = json_config['user']
cluster_pwd = json_config['pwd']
cluster_eula_username = json_config['eulas']['username']
cluster_eula_companyname = json_config['eulas']['company']
cluster_eula_jobtitle= json_config['eulas']['jobtitle']
cluster_pulse = json_config['pulse']
cluster_dsip = json_config['cluster']['data_service_ip']
cluster_networks = json_config['networks']
cluster_images = json_config['images']

# main

# # region eulas
# prism_eula_details = prism_get_eula(cluster_api,cluster_user,cluster_pwd)
# if 'userDetailsList' not in prism_eula_details['entities'][0]:
#     prism_accept_eula(cluster_api,cluster_user,cluster_pwd,cluster_eula_username,cluster_eula_companyname,cluster_eula_jobtitle)
# else:
#     print("Eulas aready accepted..")
# # endregion

# # region pulse
# prism_pulse_status = prism_get_pulse(cluster_api,cluster_user,cluster_pwd)
# if prism_pulse_status['isPulsePromptNeeded'] != False or prism_pulse_status['enable'] != cluster_pulse:
#     prism_enable_pulse(cluster_api,cluster_user,cluster_pwd,cluster_pulse)
# else:
#     print("Pulse already configured properly..")
# # endregion

# # region data service ip
# cluster_details = prism_get_cluster(cluster_api,cluster_user,cluster_pwd)
# if cluster_details['clusterExternalDataServicesIPAddress'] != cluster_dsip:
#     prism_set_dsip(cluster_api,cluster_user,cluster_pwd,cluster_dsip)
# else:
#     print("Cluster Data Service IP already configured..")
# # endregion

# region networks
# prism_networks_details = prism_get_networks(cluster_api,cluster_user,cluster_pwd)
# for network in cluster_networks:
#     for prism_network in prism_networks_details:
#         if network['name'] == prism_network['name']:
#             print("network {} present".format(network))

# for network in cluster_networks:
#     if 'ipam' in network:
#         prism_create_network(cluster_api,cluster_user,cluster_pwd,network['name'],network['vlan'],network['ipam']['address'],network['ipam']['gateway'],network['ipam']['prefix'],network['ipam']['pool'])
#     else:
#         prism_create_network(cluster_api,cluster_user,cluster_pwd,network['name'],network['vlan'])
# endregion

# region upload images (PC and ECN)
for image in cluster_images:
    prism_container_uuid = prism_get_container_uuid(cluster_api,cluster_user,cluster_pwd,image['container'])
    image_task = prism_upload_image_url(cluster_api,cluster_user,cluster_pwd,image['name'],image['description'],image['url'],prism_container_uuid)
    image_task_uuid = image_task['taskUuid']
    prism_monitor_task_v2(cluster_api,cluster_user,cluster_pwd,image_task_uuid,retry_delay_secs=10,max_attemps=30)
# endregion