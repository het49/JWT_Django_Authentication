from django.conf.urls import url
from .views import CreateUserAPIView , authenticate_user,UserRetrieveUpdateAPIView

urlpatterns = [
	url(r'^create/$',CreateUserAPIView.as_view()),
	url(r'^update/$', UserRetrieveUpdateAPIView.as_view()),
	url(r'^obtain_token/$', authenticate_user),


]