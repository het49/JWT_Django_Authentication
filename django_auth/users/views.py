import jwt
from .models import User
from django.contrib.auth.signals import user_logged_in
from django.shortcuts import render
from .serializers import  UserSerializer
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny ,IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django_auth import settings
from rest_framework_jwt.serializers import jwt_payload_handler

from rest_framework.decorators import api_view, permission_classes,parser_classes

from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.parsers import JSONParser
# Create your views here.

class CreateUserAPIView(APIView):
	#allow any user (authenticated or not) to access this url.
	permission_class = (AllowAny,)
	parser_classes = [JSONParser]

	def post(self,request):
		user = request.data

		serializer = UserSerializer(data=user)
		serializer.is_valid(raise_exception = True)
		serializer.save()

		return Response(serializer.data,status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny,])
@parser_classes([JSONParser])#if you are  using function
def authenticate_user(request):
	try:
		email = request.data['email']
		password = request.data['password']

		user = User.objects.get(email=email,password=password)
		if user:
			try:
				payload = jwt_payload_handler(user)
				token = jwt.encode(payload,settings.SECRET_KEY)
				user_details = {}

				user_details['name'] = "%s %s" % (user.first_name,user.last_name)

				user_details['token'] = token

				user_logged_in.send(sender = user.__class__,request=request,user=user)

				return Response(user_details,status=status.HTTP_200_OK)
			except Exception as e:
				raise e
		else:
			res = {'error' : 'Cann not authnticate with given credentials or Account hs been deactivated'}
			return Response(res,status=status.HTTP_403_FORBIDDEN)
	except KeyError:
		res = {'error' : 'please provide email and password'}
		return Response(res)

class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
	#Allow only authenticated user to access this url
	permission_classes = (IsAuthenticated,)
	serializer_class =  UserSerializer
	parser_classes = [JSONParser]

	def get(self,request,*args,**kwargs):
		#Serializer  to handle turning over our 'USer' object into something that can be JSONified and sent to the client
		serializer = self.serializer_class(request.user)
		return Response(serializer.data,status=status.HTTP_200_OK)

	def put(self,request,*args,**kwargs):
		serializer_data = request.data.get('user',{})

		serializer = UserSerializer(request.user,data=serializer_data,partial=True)

		serializer.is_valid(raise_exception=True)
		serializer.save()

		return Response(serializer_data,status=status.HTTP_200_OK)