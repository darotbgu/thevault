from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT, HTTP_400_BAD_REQUEST
from rest_framework.authtoken.models import Token

USERNAME_KEY = "username"
PASSWORD_KEY = "password"


class Login(ObtainAuthToken):

    def post(self, request, *args, **kwargs):

        if USERNAME_KEY not in request.POST:
            return Response({"msg": "Missing username"}, status=HTTP_400_BAD_REQUEST)
        if PASSWORD_KEY not in request.POST:
            return Response({"msg": "Missing password"}, status=HTTP_400_BAD_REQUEST)

        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if not user:
            return Response("User does not exists", status=HTTP_401_UNAUTHORIZED)
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)

        return Response({"auth_token": token.key})


@permission_classes([IsAuthenticated])
class Logout(APIView):

    def get(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        logout(request)
        return Response()


class Registration(APIView):

    def post(self, request, *args, **kwargs):

        if USERNAME_KEY not in request.POST:
            return Response({"msg": "Missing username"}, status=HTTP_400_BAD_REQUEST)
        if PASSWORD_KEY not in request.POST:
            return Response({"msg": "Missing password"}, status=HTTP_400_BAD_REQUEST)

        username = request.POST['username']
        password = request.POST['password']

        if User.objects.filter(username=username).exists():
            return Response({"msg": "User already exists"}, status=HTTP_409_CONFLICT)

        user = User.objects.create_user(username=username, password=password)
        user.save()
        response = {"success": True, "data": None, "msg": "Registered successfully"}
        return Response(response)

