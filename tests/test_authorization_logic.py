import pytest
import requests
from tools.authorization_tools import analyze_authorization_response

class MockResponse:
    def __init__(self, status_code, json_data, headers=None):
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers or {"Content-Type": "application/json"}
        import json
        self.text = json.dumps(json_data)
        
    def json(self):
        return self._json_data

def test_auth_user_matches_owner():
    # Authenticated user ID matches the resource owner → not IDOR.
    resp = MockResponse(200, {"data": {"UserId": 5, "name": "Test"}})
    result = analyze_authorization_response(
        target={"url": "http://localhost:3000/api/Addresss/1", "type": "endpoint"},
        response=resp,
        authenticated_request=True,
        baseline_status_code=401,
        baseline_authentication_required=True,
        authenticated_user_id=5
    )
    assert result["vulnerable"] is False
    assert result["confirmed"] is False
    assert result["suspected"] is False

def test_auth_user_differs_from_owner():
    # Authenticated user ID differs from the resource owner and unauthorized access is demonstrated → confirmed IDOR.
    resp = MockResponse(200, {"data": {"UserId": 1, "name": "Admin Address"}})
    result = analyze_authorization_response(
        target={"url": "http://localhost:3000/api/Addresss/1", "type": "endpoint"},
        response=resp,
        authenticated_request=True,
        baseline_status_code=401,
        baseline_authentication_required=True,
        authenticated_user_id=5
    )
    assert result["vulnerable"] is True
    assert result["suspected"] is True
    assert result["confirmed"] is False
    assert "owner IDs: 1" in result["detail"]
    assert "authenticated ID: 5" in result["detail"]

def test_missing_auth_user_id():
    # Missing authenticated user ID → inconclusive, not confirmed.
    resp = MockResponse(200, {"data": {"UserId": 1, "name": "Admin Address"}})
    result = analyze_authorization_response(
        target={"url": "http://localhost:3000/api/Addresss/1", "type": "endpoint"},
        response=resp,
        authenticated_request=True,
        baseline_status_code=401,
        baseline_authentication_required=True,
        authenticated_user_id=None
    )
    assert result["confirmed"] is False
    assert result.get("inconclusive") is True

def test_missing_owner_id_or_malformed():
    # Missing owner ID or malformed JSON → inconclusive, not confirmed.
    resp = MockResponse(200, {"data": {"some_field": "value"}})
    result = analyze_authorization_response(
        target={"url": "http://localhost:3000/api/Addresss/1", "type": "endpoint"},
        response=resp,
        authenticated_request=True,
        baseline_status_code=401,
        baseline_authentication_required=True,
        authenticated_user_id=5
    )
    assert result["confirmed"] is False
    assert result.get("inconclusive") is False

def test_list_contains_both_owned_and_foreign():
    # A list contains both owned and foreign records → identify the foreign records.
    resp = MockResponse(200, {"data": [
        {"UserId": 5, "name": "Owned"},
        {"UserId": 1, "name": "Foreign 1"},
        {"userId": 2, "name": "Foreign 2"},
    ]})
    result = analyze_authorization_response(
        target={"url": "http://localhost:3000/api/Addresss", "type": "endpoint"},
        response=resp,
        authenticated_request=True,
        baseline_status_code=401,
        baseline_authentication_required=True,
        authenticated_user_id=5
    )
    assert result["vulnerable"] is True
    assert result["suspected"] is True
    assert result["confirmed"] is False
    assert "owner IDs: 1, 2" in result["detail"]
