#!/usr/bin/python

# (c) 2017, defunct <https://keybase.io/defunct>
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


from ansible.module_utils.basic import *
from OpenSSL import crypto
from OpenSSL.crypto import _lib
from os import urandom
from binascii import hexlify
from base64 import b64encode


class PKey(crypto.PKey):
    def generate_ec_key(self, curve):
        """
        Generate a public/private key pair for curve.

        :param curve: EllipticCurve to use for key generation.
        :type curve: :py:type:`crypto._EllipticCurve`
        :return: PKey
        :rtype: PKey
        """

        ec_key = curve._to_EC_KEY()
        crypto._openssl_assert(_lib.EC_KEY_generate_key(ec_key) == 1)
        # Required for prime256v1
        crypto._openssl_assert(_lib.EC_KEY_set_asn1_flag(ec_key, 1) != crypto._ffi.NULL)  # OPENSSL_EC_NAMED_CURVE
        crypto._openssl_assert(_lib.EVP_PKEY_set1_EC_KEY(self._pkey, ec_key) == 1)
        self._initialized = True
        return self

    def generate_key(self, type, bits=0):
        if isinstance(type, crypto._EllipticCurve):
            return self.generate_ec_key(type)
        else:
            return PKey.generate_key(self, type, bits)


class KeyStore(object):
    def __init__(self, name, curve):
        """
        Keystore for public/private/certificate/CA.
        
        :param name: keystore name 
        :type name: str
        :param curve: EllipticCurve to use for key generation.
        :rtype curve: crypto._EllipticCurve
        """
        self._name = name
        self._curve = curve
        self._pkey = PKey().generate_key(curve)
        self._cert = None
        self._ca = None

    @property
    def key(self):
        return self._pkey

    @property
    def public_key(self):
        return crypto.dump_publickey(crypto.FILETYPE_PEM, self._pkey)

    @property
    def private_key(self):
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, self._pkey)

    @property
    def certificate(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self._cert)

    @certificate.setter
    def certificate(self, value):
        if not isinstance(value, crypto.X509):
            raise Exception('value must be typeof<crypto.X509>')
        self._cert = value

    @property
    def ca(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self._ca)

    @ca.setter
    def ca(self, value):
        if not isinstance(value, crypto.X509):
            raise Exception('value must be typeof<crypto.X509>')
        self._ca = value

    def set_san(self, use_ip=False):
        """
        Set the subjectAltName for the certificate.
        
        :param use_ip: Set the IP: field in the SAN.
        :type use_ip: bool
        """
        san = ['DNS:%s' % self._name]
        if use_ip:
            san.append('IP:%s' % self._name)
        self._cert.add_extensions([
            crypto.X509Extension(
                'subjectAltName', False, ', '.join(san)
            )
        ])

    def export_p12(self, passphrase):
        """
        Export PKCS12 bundle containing key/cert/cacert.

        :param passphrase: PKCS12 bundle passphrase
        :type passphrase: str
        :return: PKCS12 bundle
        """
        p12 = crypto.PKCS12()
        p12.set_ca_certificates([self._ca])
        p12.set_privatekey(self._pkey)
        p12.set_certificate(self._cert)
        p12.set_friendlyname(self._name)
        return p12.export(passphrase, maciter=2048)

    def export(self, passphrase='default'):
        """
        Export the Keystore contents into a dict.
        
        :param passphrase: PKCS12 bundle passphrase 
        :return: Serialized keystore data
        :rtype: dict
        """
        return {
            'name': self._name,
            'private_key': self.private_key,
            'public_key': self.public_key,
            'certificate': self.certificate,
            'ca': self.ca,
            'p12': b64encode(self.export_p12(passphrase))
        }


class KeyManager(object):
    def __init__(self, curve, **ca_params):
        self._p12_passphrase = hexlify(urandom(8))
        self._cakey_passphrase = hexlify(urandom(8))
        self._curve = curve
        self._validity_period = (0, 60 * 60 * 24 * 365 * 3)
        self._cakey = PKey().generate_ec_key(curve)
        careq = KeyManager.create_cert_request(self._cakey, **ca_params)
        self._cacert = KeyManager.create_certificate(careq, (careq, self._cakey), 0, (0, 60 * 60 * 24 * 365 * 3))
        self._server = KeyStore(ca_params['CN'], self._curve)
        self.sign(self._server, **ca_params)
        self._server.set_san(use_ip=True)
        self._clients = []

    def add_clients(self, names):
        """
        Create a keystore for each client name and add it to the KeyManager clients.

        :param names: A list of client names.
        :type names: list[str]
        """
        if not isinstance(names, list):
            raise Exception('names must be typeof<list>')
        for client in names:
            self.add_client(client, CN=client)

    def add_client(self, name, **params):
        keystore = KeyStore(name, self._curve)
        self.sign(keystore, **params)
        keystore.set_san()
        self._clients.append(keystore)
        return keystore

    def sign(self, keystore, **params):
        keystore.certificate = KeyManager.create_certificate(
            KeyManager.create_cert_request(keystore.key, **params),
            (self._cacert, self._cakey), 0, self.validity_period)
        keystore.ca = self._cacert

    @property
    def clients(self):
        """
        A list of client :py:type:`KeyStore`s in the :py:type:`KeyManager`
        :return: :py:type:`list<KeyStore>`
        """
        return self._clients

    @property
    def validity_period(self):
        return self._validity_period

    @validity_period.setter
    def validity_period(self, value):
        if not isinstance(value, tuple):
            raise Exception('value must be typeof<tuple>')
        self._validity_period = value

    @staticmethod
    def create_cert_request(pkey, digest="sha256", **name):
        """
        Create a certificate request.
        Arguments: pkey   - The key to associate with the request
                   digest - Digestion method to use for signing, default is sha256
                   **name - The name of the subject of the request, possible
                            arguments are:
                              C     - Country name
                              ST    - State or province name
                              L     - Locality name
                              O     - Organization name
                              OU    - Organizational unit name
                              CN    - Common name
                              emailAddress - E-mail address
        Returns:   The certificate request in an X509Req object
        """
        req = crypto.X509Req()
        subj = req.get_subject()

        for key, value in name.items():
            setattr(subj, key, value)

        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    @staticmethod
    def create_certificate(req, issuer_cert_key, serial, validity_period, digest="sha256"):
        """
        Generate a certificate given a certificate request.
        Arguments: req        - Certificate request to use
                   issuer_cert - The certificate of the issuer
                   issuer_key  - The private key of the issuer
                   serial     - Serial number for the certificate
                   not_before  - Timestamp (relative to now) when the certificate
                                starts being valid
                   not_after   - Timestamp (relative to now) when the certificate
                                stops being valid
                   digest     - Digest method to use for signing, default is sha256
        Returns:   The signed certificate in an X509 object
        """
        issuer_cert, issuer_key = issuer_cert_key
        not_before, not_after = validity_period
        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(not_before)
        cert.gmtime_adj_notAfter(not_after)
        cert.set_issuer(issuer_cert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(issuer_key, digest)
        return cert

    @property
    def cakey(self):
        """
        The password protected PEM of the CA Key.
        :return: Password protected CA KEY in PEM format.
        :rtype: str
        """
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, self._cakey, passphrase=self._cakey_passphrase)

    def export(self):
        """
        Serialize the KeyManager and all clients.
        
        :return:
        :rtype: dict
        """
        return {
            'p12_passphrase': self._p12_passphrase,
            'ca_cert': crypto.dump_certificate(crypto.FILETYPE_PEM, self._cacert),
            'ca_key': self.cakey,
            'ca_key_passphrase': self._cakey_passphrase,
            'server': self._server.export(),
            'clients': [c.export(passphrase=self._p12_passphrase) for c in self.clients]
        }


try:
    from OpenSSL import crypto

    pyopenssl_found = True
except ImportError:
    pyopenssl_found = False

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


def main():
    mod = AnsibleModule(
        argument_spec=dict(
            ca_cn=dict(required=True, type='str'),
            save_ca_key=dict(default=False, type='bool'),
            clients=dict(type='list'),
            output_path=dict(type='str'),
            curve=dict(default='prime256v1', type='str')
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )
    km = KeyManager(crypto.get_elliptic_curve(mod.params.get('curve')), CN=mod.params.get('ca_cn'))
    km.add_clients(mod.params.get('clients'))

    out = {
        'changed': True,
        'result': km.export()
    }
    mod.exit_json(**out)


if __name__ == '__main__':
    main()
