import time, base64

from fastapi import APIRouter, Response, Depends
from fastapi.responses import JSONResponse

from typing import Optional

from bless.ssh.public_keys.rsa_public_key import RSAPublicKey
from bless.ssh.public_keys.ssh_public_key_factory import get_ssh_public_key
from bless.ssh.certificate_authorities.ssh_certificate_authority_factory import get_ssh_certificate_authority
from bless.ssh.certificates.ssh_certificate_builder import SSHCertificateType
from bless.ssh.certificates.ssh_certificate_builder_factory import get_ssh_certificate_builder

from pydantic import BaseModel, Field

import keysigning.keycloak as keycloak
import keysigning.config as config

def sign_public_key(ca, pub_key_str, valid_in_seconds, user, certificate_extensions):
    """
    Using a ssh ca to sign a public key
    :param ca the ssh ca
    :param pub_key_str public key string to be signed
    :param valid_in_seconds validity of the cert
    :user the user
    :certificate_extensions
    """
    current_time = int(time.time())
    valid_before = current_time + valid_in_seconds
    valid_after = current_time
    bypass_time_validity_check = False

    cert_builder = get_ssh_certificate_builder(ca, SSHCertificateType.USER, pub_key_str)
    cert_builder.add_valid_principal(user)

    cert_builder.set_valid_before(valid_before)
    cert_builder.set_valid_after(valid_after)
    if certificate_extensions:
        for e in certificate_extensions.split(','):
            if e:
                cert_builder.add_extension(e)
    else:
        cert_builder.clear_extensions()
    
    key_id = f'request for[{user}] \
                ssh_key[{cert_builder.ssh_public_key.fingerprint}] \
                valid_from[{time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_after))}] \
                valid_to[{time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before))}]'
    cert_builder.set_key_id(key_id)
    cert = cert_builder.get_cert_file(bypass_time_validity_check)
    return cert, valid_before

class PublicKeyToSign(BaseModel):
    """
    Public key to sign
    """
    key: str = Field (
        None, title = 'base 64 encoded of the public key'
    )

    validity: Optional[int] = Field(
        None,
        title='Validity period',
        description='validity period in seconds, 0< validity < 1 day',
        gt=0,
        lt=86400,
    )

############# init ################
clusters = {}
for option in config.config['clusters']:
    clusters[option] = {
                            'path': config.get('clusters', option),
                            'ca_private_file': config.get(option, 'ca_private_file'),
                            'ca_passphrase': config.get(option, 'ca_passphrase'),
                            'max_validity': config.get(option, 'max_validity'),
                            'certificate_extensions': config.get(option, 'certificate_extensions'),
                        }

for cluster_val in clusters.values():
    if cluster_val.get('ca_private_file'):
        with open(cluster_val.get('ca_private_file'), 'rb') as reader:
            try:
                cluster_val['ca'] = get_ssh_certificate_authority(reader.read(), str.encode(cluster_val.get('ca_passphrase')))
            except:
                cluster_val['ca'] = None


## init router
router = APIRouter()


# parameter: public key, valid (must not exceed max validity)
# return {'certificate': cert,'user':",".join(set(principals)),'mail':claims['email'].lower()}
@router.post("/sign")
async def sign(publickey: PublicKeyToSign, response: Response, user: dict = Depends(keycloak.decode), ):
    try:
        # decode public key
        public_key_str = base64.b64decode(publickey.key).decode("utf-8") 
        
        # username
        username = user.get('preferred_username')
        if not username:
            return JSONResponse(status_code=400, content={'message': 'username must not empty'})
        # get the roles
        userroles = user.get('realm_access').get('roles')
        for userrole in userroles:
            if userrole in clusters:
                if publickey.validity > int(clusters.get(userrole).get('max_validity')):
                    return JSONResponse(status_code=403, content={'message': f'Validity exceeds maximum validity period of {userrole}'})
                # now sign it
                _ca = clusters.get(userrole).get('ca')
                _extensions = clusters.get(userrole).get('certificate_extensions')
                signed_cert, valid_before = sign_public_key(_ca, public_key_str, publickey.validity, username, _extensions)
                return JSONResponse({'b64cert': base64.standard_b64encode(str.encode(signed_cert)).decode("utf-8"), \
                                    'user': username, \
                                    'cluster': clusters.get(userrole).get('path'), \
                                    'email': user.get('email'),
                                    'valid_before': time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(valid_before))
                                    })
        return JSONResponse(status_code=403, content={'message': f'You do not have permission to sign a cert for any cluster'})
    except Exception as e:
        print (f"Error: {str(e)}")
        return JSONResponse(status_code=500, content={'message': f'Error: {str(e)}'})
    


