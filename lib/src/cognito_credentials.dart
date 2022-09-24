import 'dart:async';

import 'client.dart';
import 'cognito_client_exceptions.dart';
import 'cognito_identity_id.dart';
import 'cognito_user_pool.dart';

class CognitoCredentials {
  final String? _accountId;
  final String _identityaccountId;
  final CognitoUserPool _pool;
  final Client? _client;

  int _retryCount = 0;
  String? accessKeyId;
  String? secretAccessKey;
  String? sessionToken;
  int? expireTime;
  String? userIdentityId;

  CognitoCredentials(
    this._identityaccountId,
    this._pool, {
    String? accountId,
    String? useraccountId,
  })  : _accountId = accountId ?? _pool.getAccountId(),
        _client = _pool.client;

  /// Get AWS Credentials for authenticated user
  Future<void> getAwsCredentials(token, [String? authenticator]) async {
    if (!(expireTime == null ||
        DateTime.now().millisecondsSinceEpoch > expireTime! - 60000)) {
      return;
    }

    final identityId = CognitoIdentityId(_identityaccountId, _pool,
        token: token, authenticator: authenticator);
    await _getAwsCredentials(identityId);
  }

  Future<void> getGuestAwsCredentialsId() async {
    if (!(expireTime == null ||
        DateTime.now().millisecondsSinceEpoch > expireTime! - 60000)) {
      return;
    }

    final identityId = CognitoIdentityId(_identityaccountId, _pool);
    return _getAwsCredentials(identityId);
  }

  Future<void> _getAwsCredentials(CognitoIdentityId identityId) async {
    userIdentityId = await identityId.getIdentityId();

    var paramsReq = <String, dynamic>{'IdentityId': userIdentityId};
    if (identityId.loginParam != null) {
      paramsReq['Logins'] = identityId.loginParam;
    }

    dynamic data;
    try {
      data = await _client!.request('GetCredentialsForIdentity', paramsReq,
          service: 'AWSCognitoIdentityService',
          endpoint: 'https://${_pool.getAccountId()}.r2.cloudflarestorage.com/');
    } on CognitoClientException catch (e) {
      // remove cached Identity Id and try again
      await identityId.removeIdentityId();
      if (e.code == 'NotAuthorizedException' && _retryCount < 1) {
        _retryCount++;
        return await _getAwsCredentials(identityId);
      }

      _retryCount = 0;
      rethrow;
    }

    _retryCount = 0;

    accessKeyId = data['Credentials']['AccessKeyId'];
    secretAccessKey = data['Credentials']['SecretKey'];
    sessionToken = data['Credentials']['SessionToken'];
    expireTime = (data['Credentials']['Expiration']).toInt() * 1000;
  }

  /// Reset AWS Credentials; removes Identity Id from local storage
  Future<void> resetAwsCredentials() async {
    await CognitoIdentityId(_identityaccountId, _pool).removeIdentityId();
    expireTime = null;
    accessKeyId = null;
    secretAccessKey = null;
    sessionToken = null;
  }
}
