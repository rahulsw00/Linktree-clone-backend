from django.contrib import admin
from django.urls import path, include
from api.views import CreateUserView, PasswordReset, ResetPasswordAPI
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/user/register/', CreateUserView.as_view(), name="register"),
    path("api/token/", TokenObtainPairView.as_view(), name="get_token"),
    path('api/token/refresh/', TokenRefreshView.as_view(), name="refresh"),
    path("api-auth/", include("rest_framework.urls")),
    path("reset_password/", PasswordReset.as_view(), name="request_reset_password"),
    path("reset_password/<str:encoded_pk>/<str:token>/", ResetPasswordAPI.as_view(), name="reset_password"),
]
