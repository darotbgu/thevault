from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist, ValidationError
from django.db import DatabaseError
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import permission_classes
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND
from rest_framework.views import APIView

from thevault.models import AuthenticationData, Site
from thevault.consts import *


class Login(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        missing_key = validate_request_data(request.POST, [USERNAME_KEY, PASSWORD_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        username = request.POST[USERNAME_KEY]
        password = request.POST[PASSWORD_KEY]

        user = authenticate(request, username=username, password=password)
        if not user:
            return Response({ERROR_MSG_KEY: USER_NOT_EXIST_MSG}, status=HTTP_401_UNAUTHORIZED)
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)

        return Response({"auth_token": token.key,
                         "msg": SUCCESSFUL_LOGIN_MSG.format(first_name=user.first_name, last_name=user.last_name)})


@permission_classes([IsAuthenticated])
class Logout(APIView):

    def get(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        logout(request)
        # todo: add msg? catch exceptions?
        return Response()


class Registration(APIView):

    def post(self, request, *args, **kwargs):

        missing_key = validate_request_data(request.POST, [USERNAME_KEY, PASSWORD_KEY, NAME_KEY, SURNAME_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        username = request.POST[USERNAME_KEY]
        password = request.POST[PASSWORD_KEY]
        first_name = request.POST[NAME_KEY]
        last_name = request.POST[SURNAME_KEY]

        try:
            if User.objects.filter(username=username).exists():
                return Response({ERROR_MSG_KEY: CONFLICT_MSG.format(obj="User")},
                                status=HTTP_409_CONFLICT)

            user = User.objects.create_user(username=username, password=password,
                                            first_name=first_name, last_name=last_name)
            user.save()
        except (DatabaseError, ValidationError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        return Response(create_response_data(msg=SUCCESSFUL_REG_MSG))


@permission_classes([IsAuthenticated])
class Authentications(ListCreateAPIView):
    def list(self, request, *args, **kwargs):
        try:
            user_auth_data = AuthenticationData.objects.filter(user=request.user)
        except (DatabaseError, ValidationError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        return Response(create_user_auth_data_response(user_auth_data))

    def post(self, request, *args, **kwargs):
        missing_key = validate_request_data(request.POST, [USERNAME_KEY, PASSWORD_KEY, SITE_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        site_name = request.POST[SITE_KEY]
        username = request.POST[USERNAME_KEY]
        password = request.POST[PASSWORD_KEY]
        try:
            if Site.objects.filter(name=site_name).exists():
                return Response({ERROR_MSG_KEY: CONFLICT_MSG.format(obj="Site")},
                                status=HTTP_409_CONFLICT)
            site = Site(name=site_name)
            site.save()

            auth_data = AuthenticationData(user=request.user, site=site, username=username, password=password)
            auth_data.save()

            user_auth_data = AuthenticationData.objects.filter(user=request.user)
        except (DatabaseError, ValidationError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        return Response(create_user_auth_data_response(user_auth_data, msg=SUCCESSFUL_ADD_MSG))


@permission_classes([IsAuthenticated])
class AuthenticationUpdate(APIView):
    def post(self, request, site_id, *args, **kwargs):
        missing_key = validate_request_data(request.POST, [USERNAME_KEY, PASSWORD_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        username = request.POST['username']
        password = request.POST['password']

        try:
            site = Site.objects.get(pk=site_id)
        except ObjectDoesNotExist:
            return Response(status=HTTP_404_NOT_FOUND)
        except DatabaseError as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        try:
            auth_data = AuthenticationData.objects.get(site=site)
            auth_data.username = username
            auth_data.password = password
            auth_data.save()
        except (MultipleObjectsReturned, ValidationError, DatabaseError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        auth_data_dict = create_auth_data_dict(auth_data)
        return Response(create_single_auth_data_response(auth_data_dict, msg=SUCCESSFUL_UPDATE_MSG))


def validate_request_data(data, keys):
    for key in keys:
        if key not in data:
            return key
    return None


def create_auth_data_dict(auth_data):
    return {
        "site_id": auth_data.site.id,
        "site_name": auth_data.site.name,
        "username": auth_data.username,
        "password": auth_data.password
    }


def create_single_auth_data_response(auth_data, success=True, msg=None):
    return create_response_data(auth_data, success, msg)


def create_user_auth_data_response(user_auth_data, success=True, msg=None):
    data = [create_auth_data_dict(auth_data) for auth_data in user_auth_data]
    return create_response_data(data, success, msg)


def create_response_data(data=None, success=True, msg=None):
    return {
        "success": success,
        "data": data,
        "msg": msg
    }
