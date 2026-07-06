"""Tests for SessionManager and related auth helpers."""
import hashlib
from unittest.mock import MagicMock, patch

import pytest

from carconnectivity_connectors.volkswagen.auth.session_manager import SessionManager, SessionUser, Service
from carconnectivity_connectors.volkswagen.auth.we_connect_session import WeConnectSession


class TestSessionUser:
    def test_str_format(self):
        user = SessionUser(username='user@example.com', password='secret')
        assert str(user) == 'user@example.com:secret'

    def test_attributes_stored(self):
        user = SessionUser(username='u', password='p')
        assert user.username == 'u'
        assert user.password == 'p'


class TestSessionManagerHash:
    def test_generate_hash_is_sha512(self):
        user = SessionUser('a@b.com', 'pass')
        result = SessionManager.generate_hash(Service.WE_CONNECT, user)
        expected = hashlib.sha512(('WeConnect' + 'a@b.com:pass').encode()).hexdigest()
        assert result == expected

    def test_generate_hash_deterministic(self):
        user = SessionUser('a@b.com', 'pass')
        h1 = SessionManager.generate_hash(Service.WE_CONNECT, user)
        h2 = SessionManager.generate_hash(Service.WE_CONNECT, user)
        assert h1 == h2

    def test_generate_identifier_has_prefix(self):
        user = SessionUser('a@b.com', 'pass')
        identifier = SessionManager.generate_identifier(Service.WE_CONNECT, user)
        assert identifier.startswith('CarConnectivity-connector-volkswagen:')

    def test_different_users_produce_different_hashes(self):
        u1 = SessionUser('alice@example.com', 'pw1')
        u2 = SessionUser('bob@example.com', 'pw2')
        assert SessionManager.generate_hash(Service.WE_CONNECT, u1) != \
               SessionManager.generate_hash(Service.WE_CONNECT, u2)


class TestSessionManagerGetSession:
    def test_creates_we_connect_session(self):
        manager = SessionManager(tokenstore={}, cache={})
        user = SessionUser('u@example.com', 'p')
        session = manager.get_session(Service.WE_CONNECT, user)
        assert isinstance(session, WeConnectSession)

    def test_returns_same_session_for_same_user(self):
        manager = SessionManager(tokenstore={}, cache={})
        user = SessionUser('u@example.com', 'p')
        s1 = manager.get_session(Service.WE_CONNECT, user)
        s2 = manager.get_session(Service.WE_CONNECT, user)
        assert s1 is s2

    def test_loads_token_from_tokenstore(self):
        user = SessionUser('u@example.com', 'p')
        identifier = SessionManager.generate_identifier(Service.WE_CONNECT, user)
        fake_token = {'access_token': 'abc', 'refresh_token': 'xyz'}
        tokenstore = {identifier: {'token': fake_token, 'metadata': {}}}

        manager = SessionManager(tokenstore=tokenstore, cache={})
        session = manager.get_session(Service.WE_CONNECT, user)
        assert session.token == fake_token

    def test_unsupported_service_raises(self):
        manager = SessionManager(tokenstore={}, cache={})
        user = SessionUser('u@example.com', 'p')
        fake_service = MagicMock()
        fake_service.value = 'FakeService'
        with pytest.raises(ValueError):
            manager.get_session(fake_service, user)


class TestSessionManagerPersist:
    def test_persist_saves_token_and_cache(self):
        user = SessionUser('u@example.com', 'p')
        tokenstore: dict = {}
        cache: dict = {}
        manager = SessionManager(tokenstore=tokenstore, cache=cache)

        mock_session = MagicMock()
        mock_session.token = {'access_token': 'tok'}
        mock_session.metadata = {'userId': '123'}
        mock_session.cache = {'some_url': 'data'}
        manager.sessions[(Service.WE_CONNECT, user)] = mock_session

        manager.persist()

        identifier = SessionManager.generate_identifier(Service.WE_CONNECT, user)
        assert tokenstore[identifier]['token'] == {'access_token': 'tok'}
        assert tokenstore[identifier]['metadata'] == {'userId': '123'}
        assert cache[identifier] == {'some_url': 'data'}
