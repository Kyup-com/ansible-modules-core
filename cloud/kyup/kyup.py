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
short_description: create, terminate, start or stop a container in kyup.com, return container_id.
description:
    - Creates or terminates Kyup container. When created optionally waits for it to be 'running'. This module has a dependency on python-json and python-requests.
version_added: "2.3"
author: Marian Marinov <mm@kyup.com>
options:
  api_key:
    description:
      - Kyup.com API key. The key can also be supplied by setting the Environment variable KYUP_API_KEY.
    required: true
  enc_key:
    description:
      - Kyup.com encryption key. The key can also be supplied by setting the Environment variable KYUP_ENC_KEY.
    required: false
  action:
    description:
      - Action you want to perform on the container.
    required: true
  name:
    description:
      - Name of the container that you will create/operate on
    required: true
  ssh_keys:
    description:
      - Comma separated list of ssh key names, that have access to this container.
    required: false
  password:
    description:
      - Password for the root user of the container. Required when I(action) = 'create'.
    required: false
  image:
    description:
      - Template image to use when creating the container. Required when I(action) = 'create'.
    required: false
  dc_id:
    description:
      - DataCenter location ID. Required when I(action) = 'create'.
    required: false
    default: 1
  mem:
    description:
      - Memory of the container in GB. Minimum 1 GB.
    required: false
    default: 1
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
  bw:
    description:
      - Bandwidth limit for this container, in TB. Minimum 2 TB.
    required: false
    default: 2
  storage_type:
    description:
      - Choose the storage type for this container.
    required: false
    default: local
'''

EXAMPLES = '''
# Basic provisioning example
---
- hosts: kyup
  tasks:
  - name: ensure kyup container
    kyup: >
      api_key=XXXX
      enc_key=YYYY
      action=create
      image="Centos Plain"
      dc_id=1
      name=avalon
      password=e4a17265b28f6a9e8657
      ssh_keys=hackman,piele
  - add_host: name={{ container_ip }} group=containers

- hosts: containers
  tasks:
  - name: copy the hosts file
    copy: src=/etc/hosts dest=/etc/hosts


# Rebooting a container
---
- hosts: kyup
  tasks:
  - name: restart the container
    kyup: >
      api_key=XXXX
      action=restart
      name=avalon

'''

import os
import time
import base64
import md5
from Crypto.Cipher import AES

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

## Defaults for the module
# API URL
url='https://api.kyup.com/client/v1'

# Modify this counter if you want to wait for the requests, more then a minute
retries=12 # 12 x 5sec = 60 seconds


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

def api_request(module, data):
    ret = {}
    status = 0
    params = 'request=' + data
    count = retries;
    while count != 0:
        # get the response
        resp, info = fetch_url(module, url, params)
        # parse the json
        ret = module.from_json(resp.read())
        if ret['status']:
            return ret
        status = info['status']
        count -= 1
        time.sleep(5)

    if status != 200:
        module.fail_json(changed=False, msg = 'Request failed with status %d' % int(status))

    if 'status' in ret:
        if ret['status']:
            return ret
        else:
            if 'data' in ret and 'error_code' in ret['data']:
                if ret['data']['error_code'] == 101:
                    module.fail_json(changed=False, msg = 'Failed to execute request. Error code: %d Error msg: %s req: %s' % (ret['data']['error_code'], ret['data']['error'], data))
                else:
                    module.fail_json(changed=False, msg = 'Failed to execute request. Error code: %d Error msg: %s' % (ret['data']['error_code'], ret['data']['error']))
    else:
        module.fail_json(changed=False, msg = 'Req: ' + data + ' Resp: ' + ret)

def kyup_action(module, action, container_id = 0):
    req = '{"action":"cloudList","authorization_key":"%s","data":{}}'
    ret = api_request(module, req % module.params.get('api_key'))
    for container in ret['data']['list']:
        if container['name'] == module.params.get('name'):
          container_id = container['id']
          break

    if container_id == 0:
        module.exit_json(changed=False, msg = 'Could not find container id for container name %s' % module.params.get('name'))

    req = '{"action":"%s","authorization_key":"%s","data":{"container_id":%d}}'
    ret = api_request(module, req % (action, module.params.get('api_key'), int(container_id)) )
    if action == 'cloudDetails':
        return ret['data']['container']
    else:
        module.exit_json(changed=True, msg = '%s successfull' % action)

def get_task_status(module, task_id):
    req = '{"action":"getTask","authorization_key":"%s","data":{"task_id":%d}}'
    count = retries;
    while count != 0:
        ret = api_request(module, req % (module.params.get('api_key'), int(task_id)) )
        if 'container_id' in ret['data']['task']:
            return ret['data']['task']['container_id']
        count -= 1
    module.fail_json(changed=False, msg = ret)

def add_ssh_keys(module, container_id):
    key_list = {}
    ssh_keys = module.params['ssh_keys']
    if ssh_keys is None or ssh_keys == '':
        return
    # cleanup any spaces put by the user
    ssh_keys.replace(' ', '')

    for i in ssh_keys.split(','):
        key_list[i] = 0
    # get the key IDs
    req = '{"action":"%s","authorization_key":"%s","data":{%s}}'
    ret = api_request(module, req % ('sshGetKeys', module.params.get('api_key'), ''))
    for key in ret['data']['keys']:
        if key['title'] in key_list:
            key_list[key['title']] = key['key_id']
    # add the keys to the container
    key_req = '"key_id":%d,"container_id":%d'
    for key in key_list:
        if key_list[key] == 0:
            module.fail_json(changed=True, msg = 'Unable to find key ID for key %s' % key)
        api_request(module, req % ('sshInstallKey', module.params.get('api_key'), key_req % (int(key_list[key]), int(container_id) )))

def create_container(module):
    enc_key = module.params['enc_key'] or os.environ['KYUP_ENC_KEY']

    if enc_key is None:
        module.fail_json(changed=False, msg = 'ENC_KEY is required for creation of containers')

    opt = { 'name' : None, 'password' : None, 'image' : None, 'dc_id' : None }
    for i in opt:
        opt[i] =  module.params.get(i)
        if opt[i] is None:
            module.fail_json(changed=False, msg = '%s parameter is required for creating a container' % i)

    # check if the container already exists
    req = '{"action":"cloudList","authorization_key":"%s","data":{}}'
    ret = api_request(module, req % module.params.get('api_key'))
    for container in ret['data']['list']:
        if container['name'] == module.params.get('name'):
            container['ip'] = container['ip'][0:-3]
            module.exit_json(
                changed=False,
                ansible_facts = { 'container_name': container['name'], 'container_ip': container['ip'] },
                msg = 'Container %s already exists' % module.params.get('name')
            )

    storage_type = module.params['storage_type']
    if storage_type is None or storage_type == 'local':
        storage_type = 0
    elif storage_type == 'distributed':
        storage_type = 1

    container_id = 0
    req = '{"action":"cloudCreate","authorization_key":"%s","data":{"name":"%s","password":"%s","image_name":"%s","datacenter_id":%d,"storage_type":%d,"resources":{"mem":%d,"hdd":%d,"cpu":%d,"bw":%d}}}'
    ret = api_request(module, req % (
            module.params.get('api_key'),
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
        )
    if 'task_id' in ret['data']:
        if ret['data']['task_id'] > 0:
            container_id = get_task_status(module, ret['data']['task_id'])
            container = kyup_action(module, 'cloudDetails', container_id)
            add_ssh_keys(module, container_id)
            # remove the mask portion of the string
            container['ip'] = container['ip'][0:-3]
            module.exit_json(
                changed = True,
                ansible_facts = { 'container_name': container['name'], 'container_ip': container['ip'] },
                msg = 'Container: Name: %s IP: %s' % (container['name'], container['ip'])
            )
        else:
            module.fail_json(changed=True, msg = 'Invalid task_id')
    else:
        module.fail_json(changed=True, msg = 'Unable to get task_id')

def core(module):
    api_key = module.params['api_key']
    if os.environ.get('KYUP_API_KEY', None):
        api_key = os.environ['KYUP_API_KEY']
        module.params['api_key'] = api_key

    if api_key is None or api_key == '':
        module.fail_json(changed=False, msg = 'you can not continue without api_key')

    action = module.params['action']
    if action is None:
        module.fail_json(changed=False, msg = 'action parameter is required by this module')
    elif action == 'create':
        create_container(module)
    else:
        if action == 'destroy':
            kyup_action(module, 'cloudDestroy')
        elif action == 'start':
            kyup_action(module, 'cloudStart')
        elif action == 'stop':
            kyup_action(module, 'cloudStop')
        elif action == 'restart':
            kyup_action(module, 'cloudReboot')
    
def main():
    module = AnsibleModule(
        argument_spec = dict(
            api_key = dict(aliases=['API_KEY'], no_log=True),
            enc_key = dict(aliases=['ENC_KEY'], no_log=True),
            action = dict(type='str', aliases=['state', 'command', 'cmd']),
            dc_id = dict(type='int', aliases=['datacenter', 'datacenter_id', 'dc_id', 'dc'], default=1),
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
    )
    core(module)

main()
