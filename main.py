""" >>>>>>>>>> IMPORTANT <<<<<<<<<<

You will need to create a CrowdStrike API Client to use this script.
Follow the guide here: https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/

"""
from base64 import b64encode
import requests
import json
# Import modules used for getting input for client_id/client_secret.
import sys, getpass
import pprint
import csv
# Import modules used for handling exit actions.
import atexit, signal

# These lines allow us to interactively ask for the client_id and client_secret if this script
# is run interactively. Alternatively, we will read in additional input from the CLI.
# https://pymotw.com/2/getpass/
if sys.stdin.isatty():
    print('Enter CrowdStrike credentials')
    client_id = input('client_id: ')
    client_secret = getpass.getpass('client_secret: ')
else:
    client_id = sys.stdin.readline().rstrip()
    client_secret = sys.stdin.readline().rstrip()

assert client_id is not None and client_secret is not None, "You must supply both client_id and client_secret!"

access_token = None

base_url = 'https://api.crowdstrike.com/'

def revoke_token():
    """Revoke the current access token if one is current.

    Args:
        none
    """
    global access_token

    # We can only revoke an active token, so check for that and return None if there is no active token.
    if access_token is None:
        return

    # Construct the required headers to revoke the access token.
    # Note the requirement to pass a base64-encoded client_id:client_secret combination.
    request_headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'basic '+b64encode(bytes(client_id+':'+client_secret,'utf-8')).decode('utf-8')
    }
    request_data = 'token='+access_token
    request_url = base_url+'oauth2/revoke'
    result = requests.request('POST', request_url, headers=request_headers, data=request_data).status_code == 200

    # Invalidate the access token.
    access_token = None
    return result
    
# These lines ensure that the access token will be revoked on termination of this script.
atexit.register(revoke_token)
signal.signal(signal.SIGTERM, revoke_token)
signal.signal(signal.SIGINT, revoke_token)


def generate_token():
    """Generate an access token w/ the supplied client_id and client_secret.

    Args:
        none
    """
    global access_token
    
    # If there is already an active access token, revoke it.
    if access_token != None:
        revoke_token()
    
    # Construct the required headers to generate the access token.
    request_headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    request_data = 'client_id='+client_id+'&client_secret='+client_secret
    request_url = base_url+'oauth2/token'
    access_token = requests.request('POST', request_url, headers=request_headers, data=request_data).json()['access_token']


def execute_api(request_url, request_type, additional_headers = {}, request_data = None):
    """Basic function to remove this snippet of code out of every other function.

    Args:
        request_url: string, the target API URL.
        request_type: string, what type of request is being made (ie - GET, POST, DELETE).
        additional_headers: dict, any extra headers to add to the base auth headers.
        request_data: json, any data that needs to be sent, usually only required for POST.
    """
    # If the access token is not valid, generate one.
    if access_token is None:
        generate_token()
    
    # Construct the auth header for regular API queries
    request_headers = {
        'accept': 'application/json',
        'authorization': 'bearer '+access_token
    }
    # If any API calls require additional headers, add them here.
    request_headers.update(additional_headers)

    # There are a specific set of request types that can be executed.
    valid_types = {'GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'}
    if request_type not in valid_types:
        raise ValueError('execute_api: request_type must be one of {0}.'.format(valid_types))

    # Execute the request, and return the result.
    return requests.request(request_type, request_url, headers=request_headers, data=json.dumps(request_data))


def get_host_groups():
    """Retrieve all of the host groups.

    Args:
        none
    """
    request_url = base_url+'devices/combined/host-groups/v1'
    return execute_api(
        request_url = request_url,
        request_type = 'GET'
    )


def create_host_group(name, description, group_type='static', assignment_rule=''):
    """Create a new host group.

    Args:
        name: string, the name of this host group.
        description: string, the description for this host group.
        group_type: string, either static or dynamic.
        assignment_rule: string, the filter used to determine what hosts are part of this group.
    """
    # There are only two valid group_types, so we restrict it here.
    valid_types = {'static','dynamic'}
    if group_type not in valid_types:
        raise ValueError('create_host_group: group_type must be one of {0}.'.format(valid_types))

    request_url = base_url+'devices/entities/host-groups/v1'
    additional_headers = {
        'Content-Type': 'application/json'
    }
    request_data = {
        "resources": [
            {
                "name": name,
                "description": description,
                "group_type": group_type,
            }
        ]
    }
    
    if group_type == 'dynamic':
        request_data['resources'][0].update(
            {
                "assignment_rule" : assignment_rule
            }
        )

    return execute_api(
        request_url = request_url,
        request_type = 'POST',
        additional_headers = additional_headers,
        request_data = request_data
    )


def delete_host_groups(host_group_ids=[]):
    """Delete one or more host groups by referencing their IDs.

    Args:
        host_group_ids: list, one or more host group IDs to delete.
    """
    request_url = base_url+'devices/entities/host-groups/v1?ids='+'&ids='.join(host_group_ids)
    return execute_api(
        request_url = request_url,
        request_type = 'DELETE'
    )


def get_prevention_policies():
    """Retrieve all of the prevention policies.

    Args:
        none
    """
    request_url = base_url+'policy/combined/prevention/v1'
    return execute_api(
        request_url = request_url,
        request_type = 'GET'
    )


def add_host_group_to_prevention_policy(host_group_id, prevention_policy_id):
    """Add the specified host group to the specified prevention policy.

    Args:
        host_group_id: string, the host group ID to add.
        prevention_policy_id: string, the prevention policy ID to add the host group to.
    """
    request_url = base_url+'policy/entities/prevention-actions/v1?action_name=add-host-group'
    additional_headers = {
        'Content-Type': 'application/json'
    }
    request_data = {
        "action_parameters": [
            {
                "name": "group_id",
                "value": host_group_id
            }
        ],
        "ids": [
            prevention_policy_id
        ]
    }
    return execute_api(
        request_url = request_url,
        request_type = 'POST',
        additional_headers = additional_headers,
        request_data = request_data
    )


def get_sensor_update_policies():
    """Retrieve all of the sensor update policies.

    Args:
        none
    """
    request_url = base_url+'policy/combined/sensor-update/v2'
    return execute_api(
        request_url = request_url,
        request_type = 'GET'
    )


def add_host_group_to_sensor_update_policy(host_group_id, sensor_update_polcy_id):
    """Add the specified host group to the specified sensor update policy.

    Args:
        host_group_id: string, the host group ID to add.
        sensor_update_polcy_id: string, the sensor update policy ID to add the host group to.
    """
    request_url = base_url+'policy/entities/sensor-update-actions/v1?action_name=add-host-group'
    additional_headers = {
        'Content-Type': 'application/json'
    }
    request_data = {
        "action_parameters": [
            {
                "name": "group_id",
                "value": host_group_id
            }
        ],
        "ids": [
            sensor_update_polcy_id
        ]
    }
    return execute_api(
        request_url = request_url,
        request_type = 'POST',
        additional_headers = additional_headers,
        request_data = request_data
    )