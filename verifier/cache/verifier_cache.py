# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
The dictionaries defined below caches the data for the verification processes for 1 hour. The timer is reset after each update
"""
from typing import List
import uuid

from pydantic import BaseModel
import common.model.dif_presentation_exchange as dif
import fakeredis
import verifier.models as models

# TODO -> Replace this initialization with an an actual redis connection
cache = fakeredis.FakeStrictRedis(version=6)

"""
Abstraction layer for caching the data needed for the verification process. The different data object have
their own "Service" object by with the data for their cache_namespace can be manipulated.
E.g. RequestObjectService manages all entries saved in the cache with the key 'request_object:{uuid}'.
The data themself are converted as follow: pydantic model -> model_dump -> storing as json with the
functionality provided by redis/fakeredis. This approach is documented here
https://developer.redis.com/howtos/redisjson/using-python/#installing-redis

Caching / TTL: The idea is that the authorization response data expire after 1 day.

About fakeRedis: Fake redis mocks the actual redis v7 interface and serves for testing purposes. When an
actual redis connection is used the innitialization part of fakeredis at the end of this file should only
needed to bereplaced
"""
# TODO Make this abstraction layer more pyhtonic :-). Move the different services separate modules instead of using class 'service'


class BaseService:
    def __init__(self, cache: fakeredis.FakeStrictRedis, cache_namespace: str) -> None:
        self.cache = cache
        self.cache_namespace = cache_namespace

    def _get_key(self, id: str):
        return f'{self.cache_namespace}:{id}'

    def _get_raw(self, id: str) -> List[any]:
        return self.cache.json().get(self._get_key(id))

    def _set_raw(self, id: str, content: any):
        self.cache.json().set(self._get_key(id), '$', content)

    def get(self, id: str) -> models.CacheModel:
        return models.CacheModel.model_validate(self._get_raw(id))

    def set(self, obj: models.CacheModel, id: str = uuid.uuid4().hex) -> None:
        """_summary_

        Args:
            obj (BaseModel): Cached object
            expiration_time (int): Expiration time as UNIX epoche when this wil be removed
            id (str, optional): Cache identifier
        """
        self._set_raw(id, obj.model_dump())
        # Fakeredis take an unix epoche as format for the expiration time https://redis.io/commands/expireat/
        self.cache.expireat(self._get_key(id), obj.expires_at)

    def remove(self, id: str) -> None:
        self.cache.delete(self._get_key(id))

    def exists(self, id: str) -> bool:
        """Checks whether an object is chached under the id

        Args:
            id (str): Cache identifier

        Returns:
            bool: Object exists in cache
        """
        return self.cache.exists(self._get_key(id)) > 0


class RequestObjectService(BaseService):
    def __init__(self, cache: fakeredis.FakeStrictRedis) -> None:
        super().__init__(cache, 'request_object')

    def get(self, id: str) -> models.VerificationRequestObject:
        return models.VerificationRequestObject.model_validate(self._get_raw(id))


class AuthRequestToVerificationService(BaseService):
    """
    TODO Unfortunately fakeRedis doesn't support search commands at the moment https://fakeredis.readthedocs.io/en/latest/redis-commands/RedisSearch/,
    therefore this service is used to map a lookup (n-m) of an verification_management object possible with an provided authorization_request_id
    when using redis this search could be implemented by following this guide https://redis.io/docs/clients/python/#example-indexing-and-querying-json-documents

    This service is only used inside this abstraction.  Implementing an search/indexing with actual redis wont't change the interface of the consuer
    """

    def __init__(self, cache: fakeredis.FakeStrictRedis) -> None:
        super().__init__(cache, 'auth_request_to_verification_management')

    def get(self, id: str) -> models.AuthRequestVerificationManagementPair:
        return models.AuthRequestVerificationManagementPair.model_validate(self._get_raw(id))


class VerificationManagementService(BaseService):
    def __init__(self, cache: fakeredis.FakeStrictRedis, auth_req_mapping: AuthRequestToVerificationService) -> None:
        super().__init__(cache, 'verification_management')
        self.auth_req_mapping = auth_req_mapping

    def get(self, id: str) -> models.VerificationManagement:
        # The fakeredis lib doesn't allow the mapping of enums, therefore the value of the enum is assinged while de/serializing a verification management object
        verification_management = models.VerificationManagement.model_validate(self.cache.json().get(self._get_key(id)))
        verification_management.status = models.VerificationStatus(verification_management.status)
        return verification_management

    def set(self, obj: models.VerificationManagement, id: str = uuid.uuid4().hex) -> None:
        # The fakeredis lib doesn't allow the mapping of enums, therefore the value of the enum is assinged while de/serializing a verification management object
        obj.status = obj.status.value
        super().set(id=id, obj=obj)
        self.auth_req_mapping.set(
            id=obj.authorization_request_id,
            obj=models.AuthRequestVerificationManagementPair(authorization_request_id=obj.authorization_request_id, verification_management_id=id, expires_at=obj.expires_at),
        )

    def set_verification_status(self, expiresAt: int, authorization_request_id: str, status: models.VerificationStatus):
        """
        Update status of verification management by provided authorization_request
        """
        verification_management = self.get_verification_management_by_request(authorization_request_id)
        verification_management.status = status

        # When verification data are submitted the ttl should be renewed to prevent some edge case scenario where data are submitted shortly before the ttl is reached
        if status == models.VerificationStatus.SUCCESS:
            verification_management.expires_at = expiresAt
            self.cache.expireat(self._get_key(verification_management.id), verification_management.expires_at)

        self.set(id=verification_management.id, obj=verification_management)

    def get_verification_management_by_request(self, authorization_request_id: str) -> models.VerificationManagement:
        """
        Get the assigned verification management object of a given authorization_request id
        """
        verification_management_id = self.auth_req_mapping.get(authorization_request_id).verification_management_id
        verification_management = self.get(verification_management_id)
        return verification_management


class PresentationDefinitionService(BaseService):
    def __init__(self, cache: fakeredis.FakeStrictRedis) -> None:
        super().__init__(cache, 'presentation_definition')

    def get(self, id: str) -> dif.PresentationDefinition:
        return dif.PresentationDefinition.model_validate(self._get_raw(id))


class AuthorizatioResponseDataService(BaseService):
    def __init__(self, cache: fakeredis.FakeStrictRedis) -> None:
        super().__init__(cache, 'authorization_response')

    def get(self, id: str) -> models.AuthorizationResponseData:
        return models.AuthorizationResponseData.model_validate(self._get_raw(id))


# TODO Replace this m-m mapping by actual reddis search -> see AuthRequestToVerificationService
_authorization_request_to_verification_service = AuthRequestToVerificationService(cache=cache)

request_object_service = RequestObjectService(cache=cache)
verification_management_service = VerificationManagementService(cache=cache, auth_req_mapping=_authorization_request_to_verification_service)
presentation_definition_service = PresentationDefinitionService(cache=cache)
authorization_response_data_service = AuthorizatioResponseDataService(cache=cache)
