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

# main

# region eulas
prism_eula_details = prism_get_eula(cluster_api,cluster_user,cluster_pwd)
if 'userDetailsList' not in prism_eula_details['entities'][0]:
    prism_accept_eula(cluster_api,cluster_user,cluster_pwd,cluster_eula_username,cluster_eula_companyname,cluster_eula_jobtitle)
else:
    print("Eulas aready accepted..")
# endregion

# # region pulse
prism_pulse_status = prism_get_pulse(cluster_api,cluster_user,cluster_pwd)
if prism_pulse_status['isPulsePromptNeeded'] != False or prism_pulse_status['enable'] != cluster_pulse:
    prism_enable_pulse(cluster_api,cluster_user,cluster_pwd,enable_pulse=False)
else:
    print("Pulse already configured properly..")
# # endregion