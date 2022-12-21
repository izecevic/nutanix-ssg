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
cluster_pwd = json_config['pwd']

# main
# get nutanix aos package
foundation_get_aos_details =  foundation_get_aos(foundation_api)
if foundation_aos not in foundation_get_aos_details:
    print("ERROR: provided AOS package {} doesn't exist on foundation server {}".format(foundation_aos,foundation_api))
    print("List of all AOS package available on the foundation server {}: {}".format(foundation_api,foundation_get_aos_details))
    exit(1)

# generate foundation json payload
foundation_payload = foundation_generate_image_payload(foundation_config)
print(json.dumps(foundation_payload,indent=4))

# trigger and track foundation image progress
foundation_image_nodes(foundation_api,foundation_payload)
foundation_monitor_progress(foundation_api)

# update prism admin default password
prism_update_default_pwd(cluster_api,cluster_pwd)