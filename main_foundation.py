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
prism_api = json_config['cluster']['virtual_ip']
prism_user = json_config['user']
prism_pwd = json_config['pwd']

# main
# region get nutanix aos package
print("--- Retreive AOS packages section ---")
foundation_get_aos_details =  foundation_get_aos(foundation_api)
if foundation_aos not in foundation_get_aos_details:
    print("ERROR: provided AOS package {} doesn't exist on foundation server {}".format(foundation_aos,foundation_api))
    print("List of all AOS package available on the foundation server {}: {}".format(foundation_api,foundation_get_aos_details))
    exit(1)
# endregion

# region foundation launch
print("\n--- Prepare foundation payload ---")
foundation_payload = foundation_generate_image_payload(foundation_config)
print(json.dumps(foundation_payload,indent=4))
# endregion

# region foundation launch
print("\n--- Trigger foundation process ---")
foundation_image_nodes(foundation_api,foundation_payload)
foundation_monitor_progress(foundation_api)
# endregion

# region update prism admin default password
print("\n--- Update prism default password section ---")
prism_cluster_details = prism_get_cluster(prism_api,prism_user,prism_pwd)
print(prism_cluster_details)
if prism_cluster_details == 401: # (UNAUTHORIZED)
    prism_update_default_pwd(prism_api,prism_pwd,usernane="admin",default_secret="nutanix/4u")
else:
    print("Default password already updated on Nutanix cluster {}".format(prism_api))
# endregion