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

from thevault.models import Artifacts, Holocron
from thevault.consts import *


class Login(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        missing_key = validate_request_data(request.data, [USERNAME_KEY, PASSWORD_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        username = request.data[USERNAME_KEY]
        password = request.data[PASSWORD_KEY]

        user = authenticate(request, username=username, password=password)
        if not user:
            return Response({ERROR_MSG_KEY: USER_FAIL_AUTH_MSG}, status=HTTP_401_UNAUTHORIZED)
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)

        response = create_response_data(data={"authToken": token.key,
                                              "username": user.username,
                                              "firstName": user.first_name,
                                              "lastName": user.last_name})
        return Response(response)


@permission_classes([IsAuthenticated])
class Logout(APIView):

    def get(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        logout(request)
        # todo: add msg? catch exceptions?
        return Response()


class Registration(APIView):

    def post(self, request, *args, **kwargs):

        missing_key = validate_request_data(request.data, [USERNAME_KEY, PASSWORD_KEY, NAME_KEY, SURNAME_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        username = request.data[USERNAME_KEY]
        password = request.data[PASSWORD_KEY]
        first_name = request.data[NAME_KEY]
        last_name = request.data[SURNAME_KEY]

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
class ArtifactsData(ListCreateAPIView):
    def list(self, request, *args, **kwargs):
        try:
            user_artifacts = Artifacts.objects.filter(user=request.user)
        except (DatabaseError, ValidationError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        return Response(create_user_artifacts_response(user_artifacts))

    def post(self, request, *args, **kwargs):
        missing_key = validate_request_data(request.data, [JEDI_KEY, SITH_KEY, HOLOCRON_KEY, FORCE_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        crystal = request.data[HOLOCRON_KEY]
        jedi = request.data[JEDI_KEY]
        sith = request.data[SITH_KEY]
        force = request.data[FORCE_KEY]

        try:
            if Holocron.objects.filter(crystal=crystal).exists():
                return Response({ERROR_MSG_KEY: CONFLICT_MSG.format(obj="Holocron")},
                                status=HTTP_409_CONFLICT)
            holocron = Holocron(crystal=crystal)
            holocron.save()

            artifact = Artifacts(user=request.user, holocron=holocron, jedi=jedi, sith=sith, force=force)
            artifact.save()

            user_artifacts = Artifacts.objects.filter(user=request.user)
        except (DatabaseError, ValidationError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        return Response(create_user_artifacts_response(user_artifacts, msg=SUCCESSFUL_ADD_MSG))


@permission_classes([IsAuthenticated])
class ArtifactsUpdate(APIView):
    def post(self, request, holocron_id, *args, **kwargs):
        missing_key = validate_request_data(request.data, [JEDI_KEY, SITH_KEY, FORCE_KEY])
        if missing_key:
            return Response({ERROR_MSG_KEY: BAD_REQUEST_MSG.format(key=missing_key)},
                            status=HTTP_400_BAD_REQUEST)

        jedi = request.data[JEDI_KEY]
        sith = request.data[SITH_KEY]
        force = request.data[FORCE_KEY]

        try:
            holocron = Holocron.objects.get(pk=holocron_id)
        except ObjectDoesNotExist:
            return Response(status=HTTP_404_NOT_FOUND)
        except DatabaseError as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        try:
            artifact = Artifacts.objects.get(holocron=holocron)
            artifact.jedi = jedi
            artifact.sith = sith
            artifact.force = force
            artifact.save()
        except (MultipleObjectsReturned, ValidationError, DatabaseError) as exp:
            return Response(create_response_data(success=False, msg=str(exp)))

        auth_data_dict = create_artifact_dict(artifact)
        return Response(create_single_artifact_response(auth_data_dict, msg=SUCCESSFUL_UPDATE_MSG))


def validate_request_data(data, keys):
    for key in keys:
        if key not in data:
            return key
    return None


def create_artifact_dict(artifact):
    return {
        "holocron_id": artifact.holocron.id,
        "crystal": artifact.holocron.crystal,
        "jedi": artifact.jedi,
        "sith": artifact.sith,
        "force": artifact.force
    }


def create_single_artifact_response(artifact, success=True, msg=None):
    return create_response_data(artifact, success, msg)


def create_user_artifacts_response(user_artifacts, success=True, msg=None):
    data = [create_artifact_dict(artifact) for artifact in user_artifacts]
    return create_response_data(data, success, msg)


def create_response_data(data=None, success=True, msg=None):
    return {
        "success": success,
        "data": data,
        "msg": msg
    }
