#!/usr/bin/python -t
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: kyup
short_description: create, terminate, start or stop a container in kyup.com, return container_id
description:
    - Creates or terminates Kyup container. When created optionally waits for it to be 'running'. This module has a dependency on python-json and python-requests.
version_added: "0.1"
options:
  api_key:
    description:
	  - Kyup.com API key. The key can also be supplied by setting the Environment variable KYUP_API_KEY.
	required: true
	default: null
  enc_key:
    description:
      - Kyup.com encryption key. The key can also be supplied by setting the Environment variable KYUP_ENC_KEY.
    required: false
    default: null
  action:
    description:
	  - Action you want to perform on the container.
	choices: [ 'create', 'destroy', 'start', 'stop', 'restart' ]
	required: true
	default: null
	aliases: [ state, command, cmd ]
  ssh_keys:
    description:
      - Comma separated list of ssh key names, that have access to this container.
    required: false
    default: null
  container_id:
    description:
	  - ID of the container you want to operate on.
    required: false
    default: null
  password:
    description:
      - Password for the root user of the container.
    required: false
    default: null
    aliases: [ 'pass' ]
  image:
    description:
      - Template image to use when creating the container.
    required: false
    default: null
    aliases: [ 'template' ]
  dc_id:
    description:
      - DataCenter location ID.
    required: false
    default: null
    aliases: [ 'datacenter', 'datacenter_id' ]
  mem:
    description:
      - Memory of the container in GB. Minimum 1 GB.
    required: false
    default: 1
    aliases: [ 'ram' ]
  hdd:
    description:
      - Storage size in GB. Minimum 20 GB.
    required: false
    default: 20
  cpu_cores:
    description:
      - Number of CPU cores to be used. Minimum 2 CPU cores.
    required: false
    default: 2
    aliases: [ 'cpus' ]
  bw:
    description:
      - Bandwidth limit for this container, in TB. Minimum 2 TB.
    required: false
    default: 2
  storage_type:
    description:
      - Choose the storage type for this container.
    choices: [ "local", "distributed" ]
    required: false
    default: local

author: Marian Marinov <mm@kyup.com>
'''

EXAMPLES = '''
# Basic provisioning example
- kyup:
    api_key=XXXX
    ssh_keys=hackman,piele
    image=CentOS plain
'''

url='https://api.kyup.com/client/v1'

import os
import requests
import time
import base64
import md5
from Crypto.Cipher import AES

try:
    import json
except ImportError:
    import simplejson as json

# import module snippets
from ansible.module_utils.basic import *


## Code used for encryption of the passwords
blocksize = AES.block_size

def pad( data ):
    padding = blocksize - ( len(data) % blocksize )
    return data + (chr(padding) * padding)

def encrypt( key, data ):
    data = pad(data)
    m = md5.new(key)
    iv = m.hexdigest()[0:blocksize]
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return base64.b64encode( cipher.encrypt( data ) )
## End of encryption code

def kyup_action(module, container_id, action):
    api_key = module.params.get('api_key')
    req = '{"action":"%s","authorization_key":"%s","data":{"container_id":%d}}'
    count = 12; # 12 x 5sec = 60 seconds
    ret = {}
    while count != 0:
        # get the response
        resp = requests.post(url, { 'request': req % (action, api_key, container_id) } )
        # parse the json
        ret = json.loads(resp.text)
        # check if the status is OK
        if ret["status"]:
            if action == 'cloudDetails':
                return ret["data"]["container"]
            else:
                module.exit_json(changed=True, msg = "%s successfull" % action)
        time.sleep(5)
        count -= 1
    module.fail_json(changed=False, msg = "Unable to %s container %d Error code: %d Error msg: %s" % (action, container_id, ret["data"]["error_code"], ret["data"]["error"]))

def get_task_status(module, task_id):
    api_key = module.params.get('api_key')
    req = '{"action":"getTask","authorization_key":"%s","data":{"task_id":%d}}'
    count = 12; # 12 x 5sec = 60 seconds
    ret = {}
    while count != 0:
        resp = requests.post(url, { 'request': req % (api_key, task_id) } )
        ret = json.loads(resp.text)
        # Check if the status is 1 and if we have received the data hash, then check if we have a task and its status is 1
        if ret["status"] and ret["data"]["task"]["status"] == 1:
            return ret["data"]["task"]["container_id"]
        time.sleep(5)
        count -= 1
    module.fail_json(changed=False, msg = "Failed to get task status for task %d Error code: %d Error msg: %s" % (task_id, ret["data"]["error_code"], ret["data"]["error"]))

def create_container(module):
    api_key = module.params['api_key'] or os.environ['KYUP_API_KEY']
    enc_key = module.params['enc_key'] or os.environ['KYUP_ENC_KEY']

    if enc_key is None:
        module.fail_json(changed=False, msg = "ENC_KEY is required for creation of containers")

    opt = { "name" : None, "password" : None, "image" : None, "dc_id" : None }
    for i in opt:
        opt[i] =  module.params.get(i)
        if opt[i] is None:
            module.fail_json(changed=False, msg = "%s parameter is required for creating a container" % i)

    storage_type = module.params['storage_type']
    if storage_type is None or storage_type == 'local':
        storage_type = 0
    elif storage_type == 'distributed':
        storage_type = 1

    req = '{"action":"cloudCreate","authorization_key":"%s","data":{"name":"%s","password":"%s","image_name":"%s","datacenter_id":%d,"storage_type":"%s","resources":{"mem":%d,,"hdd":%d,,"cpu":%d,,"bw":%d}}}'
    req = req % (
        api_key,
        opt['name'],
        encrypt(enc_key, opt['password']),
        opt['image'],
        opt['dc_id'],
        storage_type,
        module.params.get('mem'),
        module.params.get('hdd'),
        module.params.get('cpu_cores'),
        module.params.get('bw')
        )

    container_id = 0
    resp = requests.post(url, { 'request': req })
    ret = json.loads(resp.text)
    if ret["status"]:
        task = ret["data"]["task_id"]
        if task is not None and task > 0:
            container_id = get_task_status(module, task)
            container = kyup_action(module, container_id, "cloudDetails")
            module.exit_json(
                changed = True,
                id = container_id,
                ip = container["ip"],
                name = container["name"],
                msg = "Container: Name: %s IP: %s" % (container["name"], container["ip"])
            )
        else:
            module.fail_json(changed=True, msg = "Unable to get task_id")
    else:   
        module.fail_json(changed=False, msg = "Error code: %d Error msg: %s" % (ret["data"]["error_code"], ret["data"]["error"]))

def core(module):
    def getkeyordie(k):
        v = module.params[k]
        if v is None:
            module.fail_json(msg = 'Unable to load %s' % k)
        return v

    api_key = module.params['api_key'] or os.environ['KYUP_API_KEY']
    if api_key is None:
        module.fail_json(changed=False, msg = "you can not continue without api_key")

    action = module.params['action']

    if action is None:
        module.fail_json(changed=False, msg = "action parameter is required by this module")
    elif action == 'create':
        create_container(module)
    else:
        container_id = module.params['container_id']
        if container_id is None:
            module.fail_json(changed=False, msg = "container_id parameter is required for this action")

        if action == 'destroy':
            kyup_action(module, container_id, "cloudDestroy")
        elif action == 'start':
            kyup_action(module, container_id, "cloudStart")
        elif action == 'stop':
            kyup_action(module, container_id, "cloudStop")
        elif action == 'restart':
            kyup_action(module, container_id, "cloudReboot")
    
def main():
    module = AnsibleModule(
        argument_spec = dict(
            api_key = dict(aliases=['API_KEY'], no_log=True),
            enc_key = dict(aliases=['ENC_KEY'], no_log=True),
            action = dict(type='str', aliases=['state', 'command', 'cmd']),
            container_id = dict(type='int'),
            dc_id = dict(type='int', aliases=['datacenter', 'datacenter_id']),
            name = dict(type='str'),
            image = dict(type='str', aliases=['template']),
            password = dict(type='str', aliases=['pass'], no_log=True),
            mem = dict(type='int', default=1, aliases=['ram']),
            hdd = dict(type='int', default=20),
            cpu_cores = dict(type='int', default=2, aliases=['cpus']),
            bw = dict(type='int', default=2),
            ssh_keys = dict(default=''),
            storage_type = dict(default='local', choices=['local', 'distributed']),
        ),
        mutually_exclusive = (
            ['container_id', 'name'],
            ['container_id', 'dc_id'],
            ['container_id', 'image'],
            ['container_id', 'password'],
            ['container_id', 'mem'],
            ['container_id', 'hdd'],
            ['container_id', 'cpu_cores'],
            ['container_id', 'bw'],
            ['container_id', 'storage_type'],
        ),
    )
    core(module)

main()
