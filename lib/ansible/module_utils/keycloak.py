# Copyright (c) 2017, Eike Frost <ei@kefro.st>
# -*- coding: utf-8 -*-
#
# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible.module_utils.urls import open_url
from ansible.module_utils._text import to_text
from ansible.module_utils.six.moves.urllib.parse import urlencode, quote
from ansible.module_utils.six.moves.urllib.error import HTTPError

URL_TOKEN = "{url}/realms/{realm}/protocol/openid-connect/token"
URL_CLIENT = "{url}/admin/realms/{realm}/clients/{id}"
URL_CLIENTS = "{url}/admin/realms/{realm}/clients"
URL_CLIENT_ROLES = "{url}/admin/realms/{realm}/clients/{id}/roles"
URL_CLIENT_ROLE = "{url}/admin/realms/{realm}/clients/{id}/roles/{role_id}"
URL_REALM_ROLES = "{url}/admin/realms/{realm}/roles"
URL_REALM_ROLE = "{url}/admin/realms/{realm}/roles/{role_id}"
URL_REALM_ROLE_BY_ID = "{url}/admin/realms/{realm}/roles-by-id/{id}"

URL_CLIENTTEMPLATE = "{url}/admin/realms/{realm}/client-templates/{id}"
URL_CLIENTTEMPLATES = "{url}/admin/realms/{realm}/client-templates"
URL_GROUPS = "{url}/admin/realms/{realm}/groups"
URL_GROUP = "{url}/admin/realms/{realm}/groups/{groupid}"

URL_USERS = "{url}/admin/realms/{realm}/users"
URL_USER = "{url}/admin/realms/{realm}/users/{id}"


def keycloak_argument_spec():
    """
    Returns argument_spec of options common to keycloak_*-modules

    :return: argument_spec dict
    """
    return dict(
        auth_keycloak_url=dict(type='str', aliases=['url'], required=True),
        auth_client_id=dict(type='str', default='admin-cli'),
        auth_realm=dict(type='str', required=True),
        auth_client_secret=dict(type='str', default=None),
        auth_username=dict(type='str', aliases=['username'], required=True),
        auth_password=dict(type='str', aliases=['password'], required=True, no_log=True),
        validate_certs=dict(type='bool', default=True)
    )


def camel(words):
    return words.split('_')[0] + ''.join(x.capitalize() or '_' for x in words.split('_')[1:])


class KeycloakAPI(object):
    """ Keycloak API access; Keycloak uses OAuth 2.0 to protect its API, an access token for which
        is obtained through OpenID connect
    """
    def __init__(self, module):
        self.module = module
        self.token = None
        self._connect()

    def _connect(self):
        """ Obtains an access_token and saves it for use in API accesses
        """
        self.baseurl = self.module.params.get('auth_keycloak_url')
        self.validate_certs = self.module.params.get('validate_certs')

        auth_url = URL_TOKEN.format(url=self.baseurl, realm=self.module.params.get('auth_realm'))

        payload = {'grant_type': 'password',
                   'client_id': self.module.params.get('auth_client_id'),
                   'client_secret': self.module.params.get('auth_client_secret'),
                   'username': self.module.params.get('auth_username'),
                   'password': self.module.params.get('auth_password')}

        # Remove empty items, for instance missing client_secret
        payload = dict((k, v) for k, v in payload.items() if v is not None)
        try:
            r = json.load(open_url(auth_url, method='POST',
                                   validate_certs=self.validate_certs, data=urlencode(payload)))
        except ValueError as e:
            self.module.fail_json(msg='API returned invalid JSON when trying to obtain access token from %s: %s'
                                      % (auth_url, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain access token from %s: %s'
                                      % (auth_url, str(e)),
                                  payload=payload)

        if 'access_token' in r:
            self.token = r['access_token']
            self.restheaders = {'Authorization': 'Bearer ' + self.token,
                                'Content-Type': 'application/json'}

        else:
            self.module.fail_json(msg='Could not obtain access token from %s' % auth_url)

    def get_clients(self, realm='master', filter=None):
        """ Obtains client representations for clients in a realm

        :param realm: realm to be queried
        :param filter: if defined, only the client with clientId specified in the filter is returned
        :return: list of dicts of client representations
        """
        clientlist_url = URL_CLIENTS.format(url=self.baseurl, realm=realm)
        if filter is not None:
            clientlist_url += '?clientId=%s' % filter

        try:
            return json.load(open_url(clientlist_url, method='GET', headers=self.restheaders,
                                      validate_certs=self.validate_certs))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain list of clients for realm %s: %s'
                                      % (realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain list of clients for realm %s: %s'
                                      % (realm, str(e)))

    def get_client_by_clientid(self, client_id, realm='master'):
        """ Get client representation by clientId
        :param client_id: The clientId to be queried
        :param realm: realm from which to obtain the client representation
        :return: dict with a client representation or None if none matching exist
        """
        r = self.get_clients(realm=realm, filter=client_id)
        if len(r) > 0:
            return r[0]
        else:
            return None

    def get_client_by_id(self, id, realm='master'):
        """ Obtain client representation by id

        :param id: id (not clientId) of client to be queried
        :param realm: client from this realm
        :return: dict of client representation or None if none matching exist
        """
        client_url = URL_CLIENT.format(url=self.baseurl, realm=realm, id=id)

        try:
            return json.load(open_url(client_url, method='GET', headers=self.restheaders,
                                      validate_certs=self.validate_certs))

        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg='Could not obtain client %s for realm %s: %s'
                                          % (id, realm, str(e)))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain client %s for realm %s: %s'
                                      % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain client %s for realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_id(self, client_id, realm='master'):
        """ Obtain id of client by client_id

        :param client_id: client_id of client to be queried
        :param realm: client template from this realm
        :return: id of client (usually a UUID)
        """
        result = self.get_client_by_clientid(client_id, realm)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def update_client(self, id, clientrep, realm="master"):
        """ Update an existing client
        :param id: id (not clientId) of client to be updated in Keycloak
        :param clientrep: corresponding (partial/full) client representation with updates
        :param realm: realm the client is in
        :return: HTTPResponse object on success
        """
        client_url = URL_CLIENT.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(client_url, method='PUT', headers=self.restheaders,
                            data=json.dumps(clientrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update client %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def create_client(self, clientrep, realm="master"):
        """ Create a client in keycloak
        :param clientrep: Client representation of client to be created. Must at least contain field clientId
        :param realm: realm for client to be created
        :return: HTTPResponse object on success
        """
        client_url = URL_CLIENTS.format(url=self.baseurl, realm=realm)

        try:
            return open_url(client_url, method='POST', headers=self.restheaders,
                            data=json.dumps(clientrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create client %s in realm %s: %s'
                                      % (clientrep['clientId'], realm, str(e)))

    def delete_client(self, id, realm="master"):
        """ Delete a client from Keycloak

        :param id: id (not clientId) of client to be deleted
        :param realm: realm of client to be deleted
        :return: HTTPResponse object on success
        """
        client_url = URL_CLIENT.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(client_url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete client %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_templates(self, realm='master'):
        """ Obtains client template representations for client templates in a realm

        :param realm: realm to be queried
        :return: list of dicts of client representations
        """
        url = URL_CLIENTTEMPLATES.format(url=self.baseurl, realm=realm)

        try:
            return json.load(open_url(url, method='GET', headers=self.restheaders,
                                      validate_certs=self.validate_certs))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain list of client templates for realm %s: %s'
                                      % (realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain list of client templates for realm %s: %s'
                                      % (realm, str(e)))

    def get_client_template_by_id(self, id, realm='master'):
        """ Obtain client template representation by id

        :param id: id (not name) of client template to be queried
        :param realm: client template from this realm
        :return: dict of client template representation or None if none matching exist
        """
        url = URL_CLIENTTEMPLATE.format(url=self.baseurl, id=id, realm=realm)

        try:
            return json.load(open_url(url, method='GET', headers=self.restheaders,
                                      validate_certs=self.validate_certs))
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain client templates %s for realm %s: %s'
                                      % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain client template %s for realm %s: %s'
                                      % (id, realm, str(e)))

    def get_client_template_by_name(self, name, realm='master'):
        """ Obtain client template representation by name

        :param name: name of client template to be queried
        :param realm: client template from this realm
        :return: dict of client template representation or None if none matching exist
        """
        result = self.get_client_templates(realm)
        if isinstance(result, list):
            result = [x for x in result if x['name'] == name]
            if len(result) > 0:
                return result[0]
        return None

    def get_client_template_id(self, name, realm='master'):
        """ Obtain client template id by name

        :param name: name of client template to be queried
        :param realm: client template from this realm
        :return: client template id (usually a UUID)
        """
        result = self.get_client_template_by_name(name, realm)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def update_client_template(self, id, clienttrep, realm="master"):
        """ Update an existing client template
        :param id: id (not name) of client template to be updated in Keycloak
        :param clienttrep: corresponding (partial/full) client template representation with updates
        :param realm: realm the client template is in
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTTEMPLATE.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(url, method='PUT', headers=self.restheaders,
                            data=json.dumps(clienttrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update client template %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def create_client_template(self, clienttrep, realm="master"):
        """ Create a client in keycloak
        :param clienttrep: Client template representation of client template to be created. Must at least contain field name
        :param realm: realm for client template to be created in
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTTEMPLATES.format(url=self.baseurl, realm=realm)

        try:
            return open_url(url, method='POST', headers=self.restheaders,
                            data=json.dumps(clienttrep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create client template %s in realm %s: %s'
                                      % (clienttrep['clientId'], realm, str(e)))

    def delete_client_template(self, id, realm="master"):
        """ Delete a client template from Keycloak

        :param id: id (not name) of client to be deleted
        :param realm: realm of client template to be deleted
        :return: HTTPResponse object on success
        """
        url = URL_CLIENTTEMPLATE.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete client template %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def get_groups(self, realm="master"):
        """ Fetch the name and ID of all groups on the Keycloak server.

        To fetch the full data of the group, make a subsequent call to
        get_group_by_groupid, passing in the ID of the group you wish to return.

        :param realm: Return the groups of this realm (default "master").
        """
        groups_url = URL_GROUPS.format(url=self.baseurl, realm=realm)
        try:
            return json.load(open_url(groups_url, method="GET", headers=self.restheaders,
                                      validate_certs=self.validate_certs))
        except Exception as e:
            self.module.fail_json(msg="Could not fetch list of groups in realm %s: %s"
                                      % (realm, str(e)))

    def get_group_by_groupid(self, gid, realm="master"):
        """ Fetch a keycloak group from the provided realm using the group's unique ID.

        If the group does not exist, None is returned.

        gid is a UUID provided by the Keycloak API
        :param gid: UUID of the group to be returned
        :param realm: Realm in which the group resides; default 'master'.
        """
        groups_url = URL_GROUP.format(url=self.baseurl, realm=realm, groupid=gid)
        try:
            return json.load(open_url(groups_url, method="GET", headers=self.restheaders,
                                      validate_certs=self.validate_certs))

        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg="Could not fetch group %s in realm %s: %s"
                                          % (gid, realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg="Could not fetch group %s in realm %s: %s"
                                      % (gid, realm, str(e)))

    def get_group_by_name(self, name, realm="master"):
        """ Fetch a keycloak group within a realm based on its name.

        The Keycloak API does not allow filtering of the Groups resource by name.
        As a result, this method first retrieves the entire list of groups - name and ID -
        then performs a second query to fetch the group.

        If the group does not exist, None is returned.
        :param name: Name of the group to fetch.
        :param realm: Realm in which the group resides; default 'master'
        """
        groups_url = URL_GROUPS.format(url=self.baseurl, realm=realm)
        try:
            all_groups = self.get_groups(realm=realm)

            for group in all_groups:
                if group['name'] == name:
                    return self.get_group_by_groupid(group['id'], realm=realm)

            return None

        except Exception as e:
            self.module.fail_json(msg="Could not fetch group %s in realm %s: %s"
                                      % (name, realm, str(e)))

    def create_group(self, grouprep, realm="master"):
        """ Create a Keycloak group.

        :param grouprep: a GroupRepresentation of the group to be created. Must contain at minimum the field name.
        :return: HTTPResponse object on success
        """
        groups_url = URL_GROUPS.format(url=self.baseurl, realm=realm)
        try:
            return open_url(groups_url, method='POST', headers=self.restheaders,
                            data=json.dumps(grouprep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg="Could not create group %s in realm %s: %s"
                                      % (grouprep['name'], realm, str(e)))

    def update_group(self, grouprep, realm="master"):
        """ Update an existing group.

        :param grouprep: A GroupRepresentation of the updated group.
        :return HTTPResponse object on success
        """
        group_url = URL_GROUP.format(url=self.baseurl, realm=realm, groupid=grouprep['id'])

        try:
            return open_url(group_url, method='PUT', headers=self.restheaders,
                            data=json.dumps(grouprep), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not update group %s in realm %s: %s'
                                      % (grouprep['name'], realm, str(e)))

    def delete_group(self, name=None, groupid=None, realm="master"):
        """ Delete a group. One of name or groupid must be provided.

        Providing the group ID is preferred as it avoids a second lookup to
        convert a group name to an ID.

        :param name: The name of the group. A lookup will be performed to retrieve the group ID.
        :param groupid: The ID of the group (preferred to name).
        :param realm: The realm in which this group resides, default "master".
        """

        if groupid is None and name is None:
            # prefer an exception since this is almost certainly a programming error in the module itself.
            raise Exception("Unable to delete group - one of group ID or name must be provided.")

        # only lookup the name if groupid isn't provided.
        # in the case that both are provided, prefer the ID, since it's one
        # less lookup.
        if groupid is None and name is not None:
            for group in self.get_groups(realm=realm):
                if group['name'] == name:
                    groupid = group['id']
                    break

        # if the group doesn't exist - no problem, nothing to delete.
        if groupid is None:
            return None

        # should have a good groupid by here.
        group_url = URL_GROUP.format(realm=realm, groupid=groupid, url=self.baseurl)
        try:
            return open_url(group_url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)

        except Exception as e:
            self.module.fail_json(msg="Unable to delete group %s: %s" % (groupid, str(e)))

    def get_users(self, realm='master', filter=None):
        """ Obtains user representations for users in a realm

        :param realm: realm to be queried
        :param filter: if defined, only the user with userid specified in the filter is returned
        :return: list of dicts of users representations
        """
        userlist_url = URL_USERS.format(url=self.baseurl, realm=realm)
        if filter is not None:
            userlist_url += '?userId=%s' % filter

        try:
            user_json = json.load(open_url(userlist_url, method='GET', headers=self.restheaders,
                                           validate_certs=self.validate_certs))
            return user_json
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to obtain list of clients for realm %s: %s'
                                      % (realm, str(e)))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain list of clients for realm %s: %s'
                                      % (realm, str(e)))

    def get_user_by_id(self, id, realm='master'):
        """ Obtain user representation by id

        :param id: id (not name) of user to be queried
        :param realm: realm to be queried
        :return: dict of user representation or None if none matching exists
        """
        url = URL_USER.format(url=self.baseurl, id=id, realm=realm)

        try:
            return json.load(
                open_url(url, method='GET', headers=self.restheaders, validate_certs=self.validate_certs))
        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(msg='Could not obtain user %s for realm %s: %s'
                                          % (id, realm, str(e)))
        except ValueError as e:
            self.module.fail_json(
                msg='API returned incorrect JSON when trying to obtain user %s for realm %s: %s'
                    % (id, realm, str(e)))
        except Exception as e:
            self.module.fail_json(
                msg='Could not obtain user %s for realm %s: %s'
                    % (id, realm, str(e)))

    def get_user_id(self, name, realm='master'):
        """ Obtain user id by name

        :param name: name of user to be queried
        :param realm: realm to be queried
        :return: user id (usually a UUID)
        """
        result = self.get_user_by_name(name, realm)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def get_user_by_name(self, name, realm='master'):
        """ Obtain user representation by name

        :param name: name of user to be queried
        :param realm: user from this realm
        :return: dict of user representation or None if none matching exist
        """
        result = self.get_users(realm)
        if isinstance(result, list):
            result = [x for x in result if x['username'] == name]
            if len(result) > 0:
                return result[0]
        return None

    def create_user(self, user_representation, realm="master"):
        """ Create a user in keycloak

        :param user_representation: user representation of user to be created. Must at least contain field userId
        :param realm: realm for user to be created
        :return: HTTPResponse object on success
        """
        # Keycloak wait username as key for the keycloak user username. For the
        # keycloak modules, the username is an alias of the auth_username, thus
        # cannot be used for the users.
        try:
            user_name = user_representation.pop('keycloakUsername')
        except KeyError:
            self.module.fail_json(
                msg='User name needs to be specified when creating a new user',
                user_representation=user_representation
            )
        else:
            user_representation.update({'username': user_name})
        user_url = URL_USERS.format(url=self.baseurl, realm=realm)

        try:
            return open_url(user_url, method='POST', headers=self.restheaders,
                            data=json.dumps(user_representation), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not create user %s in realm %s: %s'
                                      % (user_representation['username'], realm, str(e)),
                                  payload=user_representation)

    def update_user(self, uuid, user_representation, realm="master"):
        """ Update an existing user
        :param uuid: id of user to be updated in Keycloak
        :param user_representation: corresponding (partial/full) user representation with updates
        :param realm: realm the user is in
        :return: HTTPResponse object on success
        """
        # Keycloak response with an error 409 conflict if a username is send
        # when updating an user. To avoid this, if the user was designated by
        # its username, it is deleted.
        try:
            user_representation.pop('keycloakUsername')
        except KeyError:
            pass
        try:
            keycloak_attributes = user_representation.pop('keycloakAttributes')
        except KeyError:
            pass
        else:
            user_representation.update({'attributes': keycloak_attributes})

        user_url = URL_USER.format(url=self.baseurl, realm=realm, id=uuid)

        try:
            return open_url(user_url, method='PUT', headers=self.restheaders,
                            data=json.dumps(user_representation),
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(
                msg='Could not update user %s in realm %s: %s' % (uuid, realm, str(e)),
                user_representation=user_representation,
                user_url=user_url
            )

    def delete_user(self, id, realm="master"):
        """ Delete a user from Keycloak

        :param id: id (not userId) of user to be deleted
        :param realm: realm of user to be deleted
        :return: HTTPResponse object on success
        """
        user_url = URL_USER.format(url=self.baseurl, realm=realm, id=id)

        try:
            return open_url(user_url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete user %s in realm %s: %s'
                                      % (id, realm, str(e)))

    def get_json_from_url(self, url):
        try:
            user_json = json.load(open_url(url, method='GET', headers=self.restheaders,
                                           validate_certs=self.validate_certs))
            return user_json
        except ValueError as e:
            self.module.fail_json(msg='API returned incorrect JSON when trying to get: %s' % (url))
        except Exception as e:
            self.module.fail_json(msg='Could not obtain url: %s' % (url))

    def get_role_url(self, role_id, realm='master', client_uuid=None):
        if 'name' in role_id:
            role_name = role_id['name']
            if client_uuid:
                rolelist_url = URL_CLIENT_ROLE.format(
                    url=self.baseurl, realm=quote(realm), id=client_uuid,
                    role_id=quote(role_name))
            else:
                rolelist_url = URL_REALM_ROLE.format(
                    url=self.baseurl, realm=quote(realm), role_id=quote(role_name))
        else:
            rolelist_url = URL_REALM_ROLE_BY_ID.format(
                url=self.baseurl, realm=realm, id=role_id['uuid'])
        return rolelist_url

    def get_role(self, role_id, realm='master', client_uuid=None):
        """ Obtain client template representation by id
        :param role_id: id or name of role to be queried
        :param realm: role from this realm
        :return: dict of role representation or None if none matching exist
        """
        role_url = self.get_role_url(role_id, realm, client_uuid)

        try:
            return json.load(
                open_url(role_url, method='GET', headers=self.restheaders,
                         validate_certs=self.validate_certs))
        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                self.module.fail_json(
                    msg='Could not obtain role %s for realm %s: %s'
                        % (to_text(list(role_id.values())[0]), to_text(realm), to_text(e)))
        except ValueError as e:
            self.module.fail_json(
                msg='API returned incorrect JSON when trying to obtain role %s for realm %s: %s'
                    % (to_text(list(role_id.values())[0]), to_text(realm), to_text(e)))
        except Exception as e:
            self.module.fail_json(
                msg='Could not obtain role %s for realm %s: %s'
                    % (to_text(list(role_id.values())[0]),  to_text(realm), to_text(e)))

    def delete_role(self, role_id, realm="master"):
        """ Delete a role from Keycloak
        :param role_id: id of role (uuid or name) to be deleted
        :param realm: realm of role to be deleted
        :return: HTTPResponse object on success
        """
        role_url = URL_REALM_ROLE_BY_ID.format(url=self.baseurl, realm=quote(realm), id=quote(role_id))

        try:
            return open_url(role_url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(msg='Could not delete role %s in realm %s: %s'
                                      % (role_id, realm, to_text(e)))

    def get_role_id(self, name, realm='master', client_uuid=None):
        """ Obtain role id by name
        :param name: name of role to be queried
        :param realm: realm to be queried
        :return: role id (usually a UUID)
        """
        result = self.get_role(name, realm, client_uuid)
        if isinstance(result, dict) and 'id' in result:
            return result['id']
        else:
            return None

    def create_role(self, role_representation, realm="master", client_uuid=None):
        """ Create a role in keycloak
        :param role_representation: role representation to be created.
        :param realm: realm for role to be created
        :return: HTTPResponse object on success
        """
        if client_uuid:
            role_url = URL_CLIENT_ROLES.format(
                url=self.baseurl, realm=quote(realm), id=client_uuid)
            role_representation.pop('clientId')
        else:
            role_url = URL_REALM_ROLES.format(url=self.baseurl, realm=quote(realm))

        try:
            return open_url(role_url, method='POST', headers=self.restheaders,
                            data=json.dumps(role_representation), validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(
                msg='Could not create role %s in realm %s: %s'
                    % (to_text(role_representation['name']), to_text(realm), to_text(e)),
                payload=role_representation)

    def update_role(self, role_id, role_representation, realm="master", client_uuid=None):
        """ Update an existing role
        :param role_id: id of role to be updated in Keycloak
        :param role_representation: corresponding (partial/full) role representation with updates
        :param realm: realm the role is in
        :return: HTTPResponse object on success
        """
        role_url = self.get_role_url(role_id, realm, client_uuid)

        try:
            return open_url(role_url, method='PUT', headers=self.restheaders,
                            data=json.dumps(role_representation),
                            validate_certs=self.validate_certs)
        except Exception as e:
            self.module.fail_json(
                msg='Could not update role %s in realm %s: %s' % (
                    to_text(list(role_id.values())[0]), to_text(realm), to_text(e)),
                role_representation=role_representation,
                role_url=role_url
            )
