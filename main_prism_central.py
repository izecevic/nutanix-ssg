# import functions
from nutanix_functions import *

# check if argument was passed to the script
if len(sys.argv) == 1:
   print('ERROR: you should pass a json config file as argument to the script')
   exit(1)

# load config and variables
file_config = sys.argv[1]
json_config = json.load(open(file_config))
pc_api = json_config['pc']['virtual_ip']
pc_user = json_config['user']
pc_pwd = json_config['pwd']
pc_eula = json_config['eulas']
pc_pulse = json_config['pulse']
cluster_dns = json_config['cluster']['dns']
cluster_ntp = json_config['cluster']['ntp']
cluster_directories = json_config['directory']
pc_roles = json_config['pc_custom_role']

# main

# # region update prism admin default password
# print("--- Update prism default password section ---")
# cluster_details = prism_get_cluster(pc_api,pc_user,pc_pwd)
# if cluster_details == 401: # (UNAUTHORIZED)
#     prism_update_default_pwd(pc_api,new_secret=pc_pwd,username="admin",default_secret="Nutanix/4u")
# else:
#     print("Default password already updated on PC {}".format(pc_api))
# # end region

# # region eulas
# print("\n--- Eulas section ---")
# prism_eula_details = prism_get_eula(pc_api,pc_user,pc_pwd)
# if 'userDetailsList' not in prism_eula_details['entities'][0]:
#     prism_accept_eula(pc_api,pc_user,pc_pwd,pc_eula['username'],pc_eula['company'],pc_eula['jobtitle'])
# else:
#     print("Eulas aready accepted on PC {}".format(pc_api))
# # endregion

# # region pulse
# print("\n--- Pulse section ---")
# prism_pulse_status = prism_get_pulse(pc_api,pc_user,pc_pwd)
# if prism_pulse_status['isPulsePromptNeeded'] != False or prism_pulse_status['enable'] != pc_pulse:
#     prism_enable_pulse(pc_api,pc_user,pc_pwd,pc_pulse)
# else:
#     print("Pulse already configured on PC {}".format(pc_api))
# # endregion

# # region dns
# print("\n--- DNS section ---")
# dns_details = prism_get_dns(pc_api,pc_user,pc_pwd)
# for dns_server in cluster_dns:
#     if dns_server not in dns_details:
#         prism_add_dns(pc_api,pc_user,pc_pwd,dns_server)
#     else:
#         print("DNS {} already configured on PC {}".format(dns_server,pc_api))
# # endregion

# # region ntp
# print("\n--- NTP section ---")
# ntp_details = prism_get_ntp(pc_api,pc_user,pc_pwd)
# for ntp_server in cluster_ntp:
#     if ntp_server not in ntp_details:
#         prism_add_ntp(pc_api,pc_user,pc_pwd,ntp_server)
#     else:
#         print("NTP {} already configured on PC {}".format(ntp_server,pc_api))
# # endregion

# #region AD
# print("\n--- AD section ---")
# for directory in cluster_directories:
#     directory_details = prism_get_directory(pc_api,pc_user,pc_pwd,directory['domain'])
#     if directory_details == None:
#         prism_set_directory(pc_api,pc_user,pc_pwd,directory['name'],directory['domain'],directory['url'],directory['svc_user'],directory['svc_pwd'])
#     else:
#         print("Directory {} already configured on PC {}".format(directory['domain'],pc_api))
# # endregion

# # region role mapping
# print("\n--- Role mapping section ---")
# for directory in cluster_directories:
#     directory_details = prism_get_directory(pc_api,pc_user,pc_pwd,directory['domain'])
#     if directory_details:
#         role_mappings_details = prism_get_role_mappings(pc_api,pc_user,pc_pwd,directory['name'])
#         if not role_mappings_details:
#             for role in directory['role_mapping']:
#                 prism_set_role_mapping(pc_api,pc_user,pc_pwd,directory['name'],role['name'],role['type'],role['value'])
#         else:
#             for role in directory['role_mapping']:
#                 role_exist = False
#                 for role_detail in role_mappings_details:
#                     if role['name'] in role_detail['role']:
#                         role_exist = True # role exist
#                 if role_exist == False:
#                     prism_set_role_mapping(pc_api,pc_user,pc_pwd,directory['name'],role['name'],role['type'],role['value'])
#                 else:
#                     print("Role {} already configured on PC {}".format(role['name'],pc_api))
#     else:
#         print("Directory {} not configured on PC {}".format(directory['domain'],pc_api))
# # endregion


# region role
print("\n--- Role section ---")
permissions_uuid_list = []
for role in pc_roles:
    for permission in role['permissions']:
        permission_uuid = pc_get_permission_uuid(pc_api,pc_user,pc_pwd,permission)
        permissions_uuid_list.append(permission_uuid)

print(permissions_uuid_list)

# endregion


# region import images from PE to PC

# endregion

# region enable calm
# print("\n--- Enable Calm section ---")
# pc_calm_status = pc_check_calm(pc_api,pc_user,pc_pwd)
# print(json.dumps(pc_calm_status,indent=4))
# if pc_calm_status['service_enablement_status'] != "ENABLED":
#     pc_enable_calm_task = pc_enable_calm(pc_api,pc_user ,pc_pwd)
#     pc_enable_calm_task_uuid = pc_enable_calm_task['task_uuid']
#     prism_monitor_task_v2(pc_api,pc_user,pc_pwd,pc_enable_calm_task_uuid,retry_delay_secs=30,max_attemps=10)
# else:
#     print("Calm already enabled on PC {}".format(pc_api))
# endregion