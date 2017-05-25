algovpn.vpn
===========

Deploys strongswan with the most secure defaults available.

Role Variables
--------------

| Name           | Default Value | Description                        |
| -------------- | ------------- | -----------------------------------|
| `clients` | None | A list of client names to be used during key generation |
| `dns_servers.ipv4`| ['8.8.8.8', '8.8.4.4'] | ipv4 DNS servers. |
| `dns_servers.ipv6`| ['2001:4860:4860::8888', '2001:4860:4860::8844'] | ipv6 DNS servers. |
| `vpn_network` | 10.19.48.0/24 | ipv4 subnet to be used for the VPN network. |
| `vpn_network_ipv6` | fd9d:bc11:4020::/48 | ipv6 subnet to be used for the VPN network. |


Registered Variables
--------------------
Variables available for use after this role has been included.

| Name           | Type | Description                        |
| -------------- | ------------- | -----------------------------------|
| `keymanager` | dict(`keymanager`) | A keystore containing CA, server, client keys, certificates and passphrases. |

`keymanager` (see vpn_keymanager.py):
```
        return {
            'p12_passphrase': self._p12_passphrase,
            'ca_cert': crypto.dump_certificate(crypto.FILETYPE_PEM, self._cacert),
            'ca_key': self.cakey,
            'ca_key_passphrase': self._cakey_passphrase,
            'server': self._server.export(),
            'clients': [c.export(passphrase=self._p12_passphrase) for c in self.clients]
        }
```


Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: algovpn.vpn, vpn_clients: ['client1', 'client2']}

License
-------

MIT

Author Information
------------------

AlgoVPN