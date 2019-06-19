# Copyright (c) 2017, Eike Frost <ei@kefro.st>
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
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError

URL_TOKEN = "{url}/realms/{realm}/protocol/openid-connect/token"
URL_CLIENT = "{url}/admin/realms/{realm}/clients/{id}"
URL_CLIENTS = "{url}/admin/realms/{realm}/clients"
URL_CLIENT_ROLES = "{url}/admin/realms/{realm}/clients/{id}/roles"
URL_REALM_ROLES = "{url}/admin/realms/{realm}/roles"
URL_CLIENT_ROLES_BY_ID = "{url}/admin/realms/{realm}/clients/{id}/roles-by-id/{rid}"
URL_REALM_ROLES_BY_ID = "{url}/admin/realms/{realm}/roles-by-id/{rid}"

URL_CLIENTTEMPLATE = "{url}/admin/realms/{realm}/client-templates/{id}"
URL_CLIENTTEMPLATES = "{url}/admin/realms/{realm}/client-templates"
URL_DEFAULT_CLIENT_SCOPES = "{url}/admin/realms/{realm}/clients/{id}/default-client-scopes"
URL_OPTIONAL_CLIENT_SCOPES = "{url}/admin/realms/{realm}/clients/{id}/optional-client-scopes"
URL_GROUPS = "{url}/admin/realms/{realm}/groups"
URL_GROUP = "{url}/admin/realms/{realm}/groups/{groupid}"
URL_CLIENT_SCOPES = "{url}/admin/realms/{realm}/client-scopes"


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
                                      % (auth_url, str(e)))

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
            # Keycloak >=4.0.0 <= 6.0.0 does not update the default
            # and optional client scope passed in the client
            # represenation.
            self._update_scopes(clientrep, realm)
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
            resp = open_url(client_url, method='POST', headers=self.restheaders,
                            data=json.dumps(clientrep), validate_certs=self.validate_certs)
            # Keycloak >=4.0.0 <= 6.0.0 does not update the default
            # and optional client scope passed in the client
            # represenation.
            self._update_scopes(clientrep, realm)
            return resp
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

    def get_role_by_name(self, name, realm="master", client_id=None):
        """ Lookup a role by name. If a client is provided, find the client
            role. Otherwise, find a realm role.

            :param name: The name of the role.
            :param realm: The realm.
            :param client_id: The client which the role belongs to. If None, searches for a realm role.
        """

        role_url = URL_CLIENT_ROLES if client_id else URL_REALM_ROLES
        role_url = (role_url + '/{name}').format(url=self.baseurl, realm=realm, id=client_id, name=name)

        try:
            resp = open_url(role_url, method='GET', headers=self.restheaders,
                            validate_certs=self.validate_certs)
            assert resp.getcode() == 200
            return json.load(resp)
        except HTTPError as e:
            if e.code == 404:
                return None
            else:
                raise e
        except Exception as e:
            self.module.fail_json(
                msg="Unable to find role {name}: {error}".format(name=name, error=e))

    def create_role(self, name, realm="master", client_id=None, description='', attributes={}):
        """ Create a role. If a client is provided, craate a client
            role. Otherwise, create a realm role.

            :param name: The name of the role.
            :param realm: The realm.
            :param client_id: The  which the role belongs to. If None, searches for a realm role.
        """

        role_url = URL_CLIENT_ROLES if client_id else URL_REALM_ROLES
        role_url = role_url.format(url=self.baseurl, realm=realm, id=client_id)

        # Attributes don't seem to work here.
        body = json.dumps({'name': name, 'description': description, 'attributes': attributes})

        try:
            resp = open_url(role_url, method='POST', headers=self.restheaders,
                            data=body, validate_certs=self.validate_certs)
            assert resp.getcode() == 201
            resp_body = resp.read()
            return json.loads(resp_body) if resp_body else True
        except Exception as e:
            self.module.fail_json(
                msg="Unable to create role {name}: {error}".format(
                    name=name, error=e))

    def update_role(self, name, realm="master", client_id=None, description='', attributes={}, composites=[]):
        """ Create a role. If a client is provided, craate a client
            role. Otherwise, create a realm role.

            :param name: The name of the role.
            :param realm: The realm.
            :param client_id: The  which the role belongs to. If None, searches for a realm role.
        """

        role_url = URL_CLIENT_ROLES if client_id else URL_REALM_ROLES
        role_url = (role_url + '/{name}').format(url=self.baseurl, realm=realm, id=client_id, name=name)

        body = json.dumps({'name': name, 'description': description, 'attributes': attributes})

        try:
            resp = open_url(role_url, method='PUT', headers=self.restheaders,
                            data=body, validate_certs=self.validate_certs)
            assert resp.getcode() == 204
            resp_body = resp.read()
            if composites:
                self._set_composite_roles(name, realm, client_id, composites)
            return json.loads(resp_body) if resp_body else True
        except Exception as e:
            self.module.fail_json(
                msg="Unable to udpate role {name}: {error}".format(
                    name=name, error=e))

    def delete_role(self, name, realm="master", client_id=None):
        """ Delete a role. If a client is provided, delete the client
            role. Otherwise, delete the realm role.

            :param name: The name of the role.
            :param realm: The realm.
            :param client_id: The client which the role belongs to. If None, searches for a realm role.
        """

        role_url = URL_CLIENT_ROLES if client_id else URL_REALM_ROLES
        role_url = (role_url + '/{name}').format(url=self.baseurl, realm=realm, id=client_id, name=name)

        try:
            resp = open_url(role_url, method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
            if resp.getcode() == 204:
                return True
            self.module.fail_json(
                msg="Failed to delete role: code: {code}\n message: {message}".format(
                    code=resp.getcode(), message=resp.read()))
        except Exception as e:
            self.module.fail_json(msg="Unable to delete role {name}: {error}" .format(
                name=name, error=e))

    def _set_composite_roles(self, name, realm, client_id, composites):
        role_url = URL_CLIENT_ROLES if client_id else URL_REALM_ROLES
        role_url = (role_url + '/{name}/composites').format(
            url=self.baseurl, realm=realm, id=client_id, name=name)

        # Keycloak's API needs a list of RoleReprentation INCLUDING
        # the id. Fetch the roles by name.
        try:
            composites = [self.get_role_by_name(**self._include_realm(realm, composite)) for composite in composites]
        except Exception as e:
            e.message = 'Could not find composite roles.'
            raise e

        body = json.dumps(composites)
        resp = open_url(role_url, method='POST', headers=self.restheaders,
                        data=body, validate_certs=self.validate_certs)
        assert resp.getcode() == 204

    def _include_realm(self, realm, kwargs):
        if 'realm' not in kwargs:
            kwargs['realm'] = realm
        return kwargs

    def _update_scopes(self, clientrep, realm):
        """ Update the client's default client scopes and optional client scopes.

        :@param clientrep: the client representation.
        :@param realm: the client's realm.
        """
        client_scopes = None
        for scope_type, url in (('defaultClientScopes', URL_DEFAULT_CLIENT_SCOPES),
                                ('optionalClientScopes', URL_OPTIONAL_CLIENT_SCOPES)):
            if scope_type in clientrep:
                client_scopes = client_scopes or self.get_client_scopes(realm)
                self._update_scope_type(clientrep[scope_type], url,
                                        client_scopes, clientrep['id'], realm)

    def _update_scope_type(self, scopes, url, client_scopes, client_id, realm):
        """ Update the client's default client scopes or optional client scopes.

        :@param scopes: list of scopes to set. All other scopes will be removed. Scopes
                        that do not exist in the realm will be silently ignored.
        :@param url: the url pattern (default or optional scope url) to PUT the scope to.
        :@param client_scopes: list of realm client scopes.
        :@param realm: the client's realm.
        """
        current_scopes_url = url.format(url=self.baseurl,
                                        realm=realm, id=client_id)
        # Get the id of the scopes we want to set
        scopes = set([scope['id'] for scope in client_scopes if scope['name'] in scopes])

        current_scopes = set(map(lambda x: x['id'],
                                 json.load(open_url(current_scopes_url, method='GET',
                                                    headers=self.restheaders,
                                                    validate_certs=self.validate_certs))))

        # add missing and remove extra scopes
        for scope in (scopes ^ current_scopes):
            request_url = (url + '/{clientScopeId}').format(url=self.baseurl,
                                                            realm=realm, id=client_id,
                                                            clientScopeId=scope)
            action = 'PUT' if scope in scopes else 'DELETE'
            open_url(request_url, method=action, headers=self.restheaders,
                     validate_certs=self.validate_certs)

    def get_client_scopes(self, realm="master"):
        """ Get all the client scopes for the realm.

        :@param realm: Realm to obtain the client scopes for.
        """
        return json.load(
            open_url(URL_CLIENT_SCOPES.format(url=self.baseurl, realm=realm),
                     method='GET', headers=self.restheaders,
                     validate_certs=self.validate_certs))

    def create_client_scope(self, name, id_="", description="", protocol="openid-connect",
                            protocol_mappers=None, attributes={}, realm="master"):
        """ Get all the client scopes for the realm.
        :@param name: Name of scope. Must be unique per realm.
        :@param attributes: map of attributes
            - consent.screen.text:  The consent screen text
        :@param id_: the client scope id. Should be left empty most of the time.
        :@param protocol_mappers:  map of protocol mappers.
            - id
        """
        body = {"name": name, "description": description, "id": id_, "protocol": protocol,
                "protocolMappers": protocol_mappers, "attributes": attributes}
        body = dict([(k, v) for k, v in body.items() if v])
        body = json.dumps(body)
        try:
            resp = open_url(URL_CLIENT_SCOPES.format(url=self.baseurl, realm=realm),
                            method='POST', data=body, headers=self.restheaders,
                            validate_certs=self.validate_certs)
            if resp.getcode() == 201:
                return True
            else:
                self.module.fail_json(
                    msg="Failed to create scope: code: {code}\n message: {message}".format(
                        code=resp.getcode(), message=resp.read()))
        except Exception as e:
            self.module.fail_json(
                msg="Failed to create scope: message: {message}".format(
                    code=resp.getcode(), message=e))

    def update_client_scope(self, name, id_, description="", protocol="openid-connect",
                            protocol_mappers=None, attributes={}, realm="master"):
        """ Update a client scopes for the realm.
        :@param name: Name of scope. Must be unique per realm.
        :@param attributes: map of attributes
            - consent.screen.text:  The consent screen text
        :@param id_: the client scope id. Should be left empty most of the time.
        :@param protocol_mappers:  map of protocol mappers.
            - id: ID
        """
        body = {"name": name, "description": description, "id": id_, "protocol": protocol,
                "protocolMappers": protocol_mappers, "attributes": attributes}
        body = dict([(k, v) for k, v in body.items() if v])
        body = json.dumps(body)
        try:
            resp = open_url((URL_CLIENT_SCOPES + "/{id_}").format(url=self.baseurl, id_=id_, realm=realm),
                            method='PUT', data=body, headers=self.restheaders,
                            validate_certs=self.validate_certs)
            if resp.getcode() == 200:
                return True
            else:
                self.module.fail_json(
                    msg="Failed to update scope: code: {code}\n message: {message}".format(
                        code=resp.getcode(), message=resp.read()))
        except Exception as e:
            self.module.fail_json(
                msg="Failed to update scope: message: {message}".format(
                    code=resp.getcode(), message=e))

    def delete_client_scope(self, name=None, id_=None, realm="master"):
        """ Get all the client scopes for the realm.

        :@param realm: Realm to obtain the client scopes for.
        """
        if id_ is None and name is None:
            self.module.fail_json(msg="Client scope name or id must be provided to delete scope.")
        if id_ is None:
            try:
                id_ = [scope['id'] for scope in
                       self.get_client_scopes(realm) if scope['name'] == name]
                id_ = id_[0]
            except Exception as e:
                self.module.fail_json(msg="Unable to find scope {name}: {error}" .format(
                    name=name, error=e))
        try:
            resp = open_url((URL_CLIENT_SCOPES + "/{id_}").format(url=self.baseurl, id_=id_, realm=realm),
                            method='DELETE', headers=self.restheaders,
                            validate_certs=self.validate_certs)
            if resp.getcode() == 204:
                return True
            else:
                self.module.fail_json(
                    msg="Failed to delete scope: code: {code}\n message: {message}".format(
                        code=resp.getcode(), message=resp.read()))
        except Exception as e:
            self.module.fail_json(
                msg="Failed to delete scope: message: {message}".format(
                    code=resp.getcode(), message=e))
