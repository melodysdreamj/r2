import 'dart:async';

import 'client.dart';
import 'cognito_user_pool.dart';

class CognitoIdentityId {
  String? identityId;
  final String _identityPoolId;
  final CognitoUserPool _pool;
  final Client? _client;
  final String? _accountId;
  final String _identityIdKey;
  final String _authenticator;
  final String? _token;
  Map<String, String?>? _loginParam;

  CognitoIdentityId(this._identityPoolId, this._pool,
      {String? authenticator, String? token})
      : _accountId = _pool.getAccountId(),
        _client = _pool.client,
        _identityIdKey = 'aws.cognito.identity-id.$_identityPoolId',
        _token = token,
        _authenticator = authenticator ??
            '${_pool.getAccountId()}.r2.cloudflarestorage.com/${_pool.getUserPoolId()}' {
    if (_token != null) {
      _loginParam = {
        _authenticator: _token,
      };
    }
  }

  Map<String, String?>? get loginParam => _loginParam;

  Future<String?> getIdentityId() async {
    var identityId = await _pool.storage.getItem(_identityIdKey);
    if (identityId != null) {
      this.identityId = identityId;
      return identityId;
    }

    final paramsReq = <String, dynamic>{'IdentityPoolId': _identityPoolId};

    if (_loginParam != null) {
      paramsReq['Logins'] = _loginParam;
    }

    final data = await _client!.request('GetId', paramsReq,
        service: 'AWSCognitoIdentityService',
        endpoint: 'https://${_pool.getAccountId()}.r2.cloudflarestorage.com/');

    this.identityId = data['IdentityId'];
    await _pool.storage.setItem(_identityIdKey, this.identityId);

    return this.identityId;
  }

  /// Remove AWS Identity Id from storage
  Future<String?> removeIdentityId() async {
    final identityIdKey = 'aws.cognito.identity-id.$_identityPoolId';
    return await _pool.storage.removeItem(identityIdKey);
  }
}
