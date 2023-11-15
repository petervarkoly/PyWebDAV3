#Copyright (c) 1999 Christian Scholz (ruebe@aachen.heimat.de)
#
#This library is free software; you can redistribute it and/or
#modify it under the terms of the GNU Library General Public
#License as published by the Free Software Foundation; either
#version 2 of the License, or (at your option) any later version.
#
#This library is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#Library General Public License for more details.
#
#You should have received a copy of the GNU Library General Public
#License along with this library; if not, write to the Free
#Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
#MA 02111-1307, USA

from __future__ import absolute_import
from __future__ import print_function
from .fileauth import DAVAuthHandler
import ldap
import os

class LdapAuthHandler(DAVAuthHandler):
    """
    Provides authentication based on a ldap server
    """

    def get_userinfo(self,user,pw,command):
        """ authenticate user """

        # Commands that need write access
        Ldap=self._config.LDAP
        conn   = ""
        result   = ""
        try:
            self._log('LDAP Config: {} {} {} {}'.format(Ldap.uri,Ldap.version,Ldap.user,Ldap.password))
            conn = ldap.initialize(Ldap.uri)
            conn.protocol_version = int(Ldap.version)
            conn.simple_bind_s(Ldap.user, Ldap.password)
        except Exception as e:
            self._log('Generic ldap error {}'.format(e))
            return 0

        try:
            result = conn.search_s(Ldap.base,ldap.SCOPE_SUBTREE, Ldap.filter.format(user),['unixHomeDirectory','memberOf','uidNumber'])
        except Exception as e:
            self._log('Can not find user {} {}'.format(user,e))
            return 0

        if len(result) == 0 or not result[0][0]:
            self._log('Result {}'.format(result))
            self._log('Authentication failed for user %s' % user)
            return 0
        else:
            try:
                conn.simple_bind_s(result[0][0], pw)
                self._log('Authentication successfully for user %s' % user)
                os.setuid(int(result[0][1]['uidNumber'][0].decode('utf-8')))
                self.IFACE_CLASS.directory = result[0][1]['unixHomeDirectory'][0].decode('utf-8')
                return 1
            except Exception as e:
                self._log('Authentication failed for user {} {}'.format(user,e))

        self._log('Authentication failed for user %s' % user)
        return 0

