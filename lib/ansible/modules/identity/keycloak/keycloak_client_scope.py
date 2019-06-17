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
module: keycloak_client_scope

short_description: This module enables the management of KeyCloak client scopes.

version_added: "2.9"

description:
    - "The keycloak_client_scope module enables the management of KeyCloak client scopes through
       the KeyCloak Rest Interface. It has been tested against keycloak 4.8.x"
    - "This module uses the KeyCloak rest API. Most of the time, it should be run as a local_action
       so that the calls are made locally."

options:
    realm:
        description:
            - The name of the realm the client scope will be created in.
        required: true
    name:
        description:
            - The name of the client scope. Must be unique.
        required: true
    id:
        description:
            - The scope's id. Keycloak will generate a UUID if not specified.
        required: false
    description:
        description:
            - Client scope description
        required: false
    state:
        description:
            - The name of the client to create the role in. If left empty the role is created in the realm.
        default: "present"
        choices: ["present", "absent"]
        required: false
    attributes:
        description:
            - client scope attributes.
        suboptions:
            consent.screen.text:
                description:
                    - The text to display on the consent screen.
        required: false
    protocol_mappers:
        description:
            - Protocol mappers that are added when this scope is present.
            - Must include:
                - id
        required: false
        type: list
        alias:
            protocolMappers

extends_documentation_fragment:
    - keycloak

author:
    - Jonathan Villemaire-Krajden (@odontomachus)
'''

EXAMPLES = '''
# Create a client scope
- name: Create a realm role
  local_action:
    module: keycloak_client_scope
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    name: ansible
    state: present
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
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        description=dict(type='str'),
        attributes=dict(type='dict'),
        protocol_mappers=dict(type='list', elements='dict', default=[]),
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
                                  description=module.params.get('description'))
            result['changed'] = True
        # Setting the attributes doesn't work on post; only on put.
        resp = kc.update_role(name, realm, client_id,
                              description=module.params.get('description'),
                              attributes=module.params.get('attributes'),
                              composites=module.params.get('composites'))
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
