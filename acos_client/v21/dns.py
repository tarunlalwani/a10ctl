# Copyright (C) 2016, A10 Networks Inc. All rights reserved.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base


class DNS(base.BaseV21):

    def set(self, primary=None, secondary=None, suffix=None, **kwargs):
        settings = {}

        if primary is not None:
            settings['primary_dns'] = primary

        if secondary is not None:
            settings['secondary_dns'] = secondary

        if suffix is not None:
            settings['dns_suffix'] = suffix

        payload = {'dns': settings}

        return self._post("network.dns.server.set", payload, **kwargs)
