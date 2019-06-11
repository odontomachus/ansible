#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: keycloak_role

short_description: This module enables the management of KeyCloak realm and client roles.

version_added: "2.9"

description:
    - "The keycloak_role module enables the management of KeyCloak realm and client roles through
       the KeyCloak Rest Interface. It has been tested against keycloak 5.x."
    - "This module uses the KeyCloak rest API. Most of the time, it should be run as a local_action
       so that the calls are made locally."

options:
    auth_url:
        description:
            - The base url ending in /auth to authenticate against for the KeyCloak API
    auth_realm:
        description:
            - The realm the client used for authenticating against the API is in
        required: false
        default: master
    auth_client_id:
        description:
            - The client to authenticate against to login to the KeyCloak API
        default: admin-cli
        required: false
    auth_client_secret:
        description:
            - The client secret for the client to authenticate against
        required: false
    auth_username:
        description:
            - The username to login to the API with
    validate_certs:
        description:
            - Whether to validate the certificate for KeyCloak
        default: true
    auth_password:
        description:
            - The password of the user to login to the API with
    realm:
        description:
            - The name of the realm the role will be created in.
        required: true
    client_id:
        description:
            - The id (not the name or the client_id used for authentication) of the client to
              create the role in. If left empty the role is created in the realm.
        required: false
    name:
        description:
            - The name of the role
        required: true
    state:
        description:
            - The name of the client to create the role in. If left empty the role is created in the realm.
        default: "present"
        choices: ["present", "absent"]
        required: false
    attributes:
        description:
            - Key-value pairs stored as role attributes in KeyCloak.
        required: false
    description:
        description:
            - Role description
        required: false

author:
    - Jonathan Villemaire-Krajden (@odontomachus)
'''

EXAMPLES = '''
# Create a realm role
- name: Create an ansible role
  local_action:
    module: keycloak_role
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    client_id: test
    state: present
    attributes:
      world:
        - hello world
      mars:
        - hello mars
'''

RETURN = '''
changed:
    description: Whether the action changed the state
    type: str
    returned: always
response:
    description: The response from the KeyCloak API
    type: requests.Response
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.keycloak import (
    KeycloakAPI,
    keycloak_argument_spec,
)


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        **keycloak_argument_spec(),
        realm=dict(type='str', required=True),
        client_id=dict(type='str', required=True),
        name=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        description=dict(type='str'),
        attributes=dict(type='dict')
    )

    result = dict(
        changed=False,
        response=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    if module.check_mode:
        module.exit_json(**result)

    realm = module.params.get('realm')
    client_id = module.params.get('client_id')
    name = module.params.get('name')
    state = module.params.get('state')

    # Obtain access token, initialize API
    kc = KeycloakAPI(module)

    role = kc.get_role_by_name(name, realm, client_id)
    resp = role
    if state == 'present':
        if role is None:
            resp = kc.create_role(name, realm, client_id,
                                  description=module.params.get('description'),
                                  attributes=module.params.get('attributes'))
            result['changed'] = True
        # Setting the attributes doesn't work on post; only on put.
        resp = kc.update_role(name, realm, client_id,
                              description=module.params.get('description'),
                              attributes=module.params.get('attributes'))
        result['changed'] |= resp == role
    elif state == 'absent' and role is not None:
        resp = kc.delete_role(name, realm, client_id)
        result['changed'] = True
    result['response'] = resp
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
